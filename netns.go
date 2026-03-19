// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"runtime"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

// createTUNInNamespace creates a TUN device inside the given network namespace.
//
// In rootless podman, the process runs inside a user namespace where we can
// enter the container netns but cannot return to the initial netns (which
// belongs to the parent user namespace). To handle this, we use a sacrificial
// goroutine: it calls LockOSThread to pin itself to an OS thread, enters the
// container netns one-way, creates the TUN, sends the fd back via a channel,
// and exits. The pinned thread is discarded by the Go runtime.
//
// This permanently leaks one OS thread. Together with configureInterface,
// a total of two OS threads are leaked per process lifetime.
func createTUNInNamespace(nsPath, tunName string, mtu int) (tun.Device, error) {
	type result struct {
		fd  int
		err error
	}
	ch := make(chan result, 1)

	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread — this thread will be stuck in the container
		// netns and must be discarded by the runtime.

		targetNS, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			ch <- result{err: fmt.Errorf("open netns %s: %w", nsPath, err)}
			return
		}
		defer unix.Close(targetNS)

		if err := unix.Setns(targetNS, unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("setns: %w", err)}
			return
		}

		// Create the TUN device with IFF_TUN | IFF_NO_PI only.
		// We don't use IFF_VNET_HDR because the caller wraps the fd
		// in a simple tun.Device that reads/writes raw IP packets.
		fd, err := createRawTUN(tunName)
		if err != nil {
			ch <- result{err: fmt.Errorf("createRawTUN: %w", err)}
			return
		}

		if err := setLinkMTU(tunName, mtu); err != nil {
			unix.Close(fd)
			ch <- result{err: fmt.Errorf("setLinkMTU: %w", err)}
			return
		}

		ch <- result{fd: fd}
	}()

	r := <-ch
	if r.err != nil {
		return nil, r.err
	}

	tunFile := os.NewFile(uintptr(r.fd), "tun-fd")
	return newFDTUN(tunFile, tunName, mtu), nil
}

// createRawTUN opens /dev/net/tun and creates a TUN device with
// IFF_TUN | IFF_NO_PI (no packet info header, no VNET_HDR).
func createRawTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF: %w", err)
	}

	return fd, nil
}

// configureInterface sets up the TUN interface inside the container's network
// namespace: brings up loopback and the TUN, assigns IPs, adds default routes.
// Use --dns=100.100.100.100 with podman to configure MagicDNS.
//
// This enters the container netns on a locked OS thread. In rootless podman,
// we cannot return to the initial netns, so the locked thread stays in the
// container ns and is discarded by the Go runtime when the goroutine exits.
//
// This permanently leaks one OS thread. Together with createTUNInNamespace,
// a total of two OS threads are leaked per process lifetime.
func configureInterface(nsPath, tunName string, ip4, ip6 netip.Addr, mtu int) error {
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Don't unlock — this thread will be stuck in the container ns
		// and should be discarded by the runtime.

		targetNS, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errCh <- fmt.Errorf("open target netns %s: %w", nsPath, err)
			return
		}
		defer unix.Close(targetNS)

		if err := unix.Setns(targetNS, unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("setns to target: %w", err)
			return
		}

		// Now in the container namespace. Configure everything.
		errCh <- configureWithNetlink(tunName, ip4, ip6, mtu)
	}()
	return <-errCh
}

// configureWithNetlink uses raw netlink/ioctl to configure the interface.
func configureWithNetlink(tunName string, ip4, ip6 netip.Addr, mtu int) error {
	if err := setLinkUp("lo"); err != nil {
		return fmt.Errorf("bringing up loopback: %w", err)
	}

	if err := setLinkMTU(tunName, mtu); err != nil {
		return fmt.Errorf("setting MTU: %w", err)
	}
	if err := setLinkUp(tunName); err != nil {
		return fmt.Errorf("bringing up %s: %w", tunName, err)
	}

	if ip4.IsValid() {
		if err := addAddr4(tunName, ip4); err != nil {
			return fmt.Errorf("adding IPv4 address: %w", err)
		}
		if err := addRoute4Default(tunName); err != nil {
			return fmt.Errorf("adding default route: %w", err)
		}
	}

	if ip6.IsValid() {
		if err := addAddr6(tunName, ip6); err != nil {
			fmt.Fprintf(os.Stderr, "netavark-tailscale-plugin: warning: adding IPv6 address: %v\n", err)
		} else if err := addRoute6Default(tunName); err != nil {
			fmt.Fprintf(os.Stderr, "netavark-tailscale-plugin: warning: adding IPv6 default route: %v\n", err)
		}
	}

	return nil
}

// setLinkUp brings a network interface up using ioctl.
func setLinkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}

	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	flags := ifr.Uint16()
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	ifr.SetUint16(flags)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// setLinkMTU sets the MTU on a network interface.
func setLinkMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	return unix.IoctlIfreq(fd, unix.SIOCSIFMTU, ifr)
}

// netlinkRequest sends a netlink message and expects a single NLMSG_ERROR
// response (errno 0 = ACK). This is only suitable for mutation operations
// (RTM_NEWADDR, RTM_NEWROUTE) with NLM_F_ACK; it will reject multipart
// responses that require looping.
func netlinkRequest(proto int, data []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return err
	}
	if err := unix.Sendto(fd, data, 0, sa); err != nil {
		return err
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	if n < unix.SizeofNlMsghdr {
		return fmt.Errorf("short netlink response")
	}

	e := binary.NativeEndian
	msgLen := e.Uint32(buf[0:4])
	if int(msgLen) > n {
		return fmt.Errorf("netlink response truncated: header says %d bytes, got %d", msgLen, n)
	}
	msgType := e.Uint16(buf[4:6])
	msgFlags := e.Uint16(buf[6:8])

	// Reject multipart responses — this function only handles single ACKs.
	if msgFlags&unix.NLM_F_MULTI != 0 || msgType == unix.NLMSG_DONE {
		return fmt.Errorf("unexpected multipart netlink response (type=%d, flags=0x%x)", msgType, msgFlags)
	}

	if msgType == unix.NLMSG_ERROR {
		if n >= unix.SizeofNlMsghdr+4 {
			errno := int32(e.Uint32(buf[unix.SizeofNlMsghdr : unix.SizeofNlMsghdr+4]))
			if errno == 0 {
				return nil
			}
			return fmt.Errorf("netlink error: %w", unix.Errno(-errno))
		}
	}
	return fmt.Errorf("unexpected netlink response type %d", msgType)
}

// getIfindex returns the interface index for the named interface.
func getIfindex(name string) (int32, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFINDEX, ifr); err != nil {
		return 0, err
	}
	return int32(ifr.Uint32()), nil
}

// addAddr4 adds an IPv4 /32 address to the named interface via netlink.
//
// Netlink attributes must be aligned to NLA_ALIGNTO (4 bytes). The attribute
// payloads used here (4-byte IPv4 addr) produce naturally aligned lengths (8).
func addAddr4(name string, addr netip.Addr) error {
	ifindex, err := getIfindex(name)
	if err != nil {
		return err
	}

	hdrLen := unix.SizeofNlMsghdr
	ifaLen := 8 // sizeof(struct ifaddrmsg)
	rtaLen := 4 + 4 // rta_hdr (4) + IPv4 addr (4) = 8, naturally 4-byte aligned

	totalLen := hdrLen + ifaLen + 2*rtaLen // IFA_LOCAL + IFA_ADDRESS
	buf := make([]byte, totalLen)
	e := binary.NativeEndian

	e.PutUint32(buf[0:4], uint32(totalLen))
	e.PutUint16(buf[4:6], unix.RTM_NEWADDR)
	e.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE)
	e.PutUint32(buf[8:12], 1)
	e.PutUint32(buf[12:16], 0)

	off := hdrLen
	buf[off+0] = unix.AF_INET
	buf[off+1] = 32
	buf[off+2] = 0
	buf[off+3] = unix.RT_SCOPE_UNIVERSE
	e.PutUint32(buf[off+4:off+8], uint32(ifindex))

	ip := addr.As4()

	// IFA_LOCAL
	off += ifaLen
	e.PutUint16(buf[off:off+2], uint16(rtaLen))
	e.PutUint16(buf[off+2:off+4], unix.IFA_LOCAL)
	copy(buf[off+4:off+8], ip[:])

	// IFA_ADDRESS — for point-to-point TUN interfaces, some kernel versions
	// require both IFA_LOCAL and IFA_ADDRESS to be set explicitly.
	off += rtaLen
	e.PutUint16(buf[off:off+2], uint16(rtaLen))
	e.PutUint16(buf[off+2:off+4], unix.IFA_ADDRESS)
	copy(buf[off+4:off+8], ip[:])

	return netlinkRequest(unix.NETLINK_ROUTE, buf)
}

// addAddr6 adds an IPv6 /128 address to the named interface via netlink.
//
// Netlink attributes must be aligned to NLA_ALIGNTO (4 bytes). The attribute
// payloads used here (16-byte IPv6 addr) produce naturally aligned lengths (20).
func addAddr6(name string, addr netip.Addr) error {
	ifindex, err := getIfindex(name)
	if err != nil {
		return err
	}

	hdrLen := unix.SizeofNlMsghdr
	ifaLen := 8
	rtaLen := 4 + 16 // rta_hdr (4) + IPv6 addr (16) = 20, naturally 4-byte aligned

	totalLen := hdrLen + ifaLen + 2*rtaLen // IFA_LOCAL + IFA_ADDRESS
	buf := make([]byte, totalLen)
	e := binary.NativeEndian

	e.PutUint32(buf[0:4], uint32(totalLen))
	e.PutUint16(buf[4:6], unix.RTM_NEWADDR)
	e.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE)
	e.PutUint32(buf[8:12], 1)
	e.PutUint32(buf[12:16], 0)

	off := hdrLen
	buf[off+0] = unix.AF_INET6
	buf[off+1] = 128
	buf[off+2] = 0
	buf[off+3] = unix.RT_SCOPE_UNIVERSE
	e.PutUint32(buf[off+4:off+8], uint32(ifindex))

	ip := addr.As16()

	// IFA_LOCAL
	off += ifaLen
	e.PutUint16(buf[off:off+2], uint16(rtaLen))
	e.PutUint16(buf[off+2:off+4], unix.IFA_LOCAL)
	copy(buf[off+4:off+20], ip[:])

	// IFA_ADDRESS
	off += rtaLen
	e.PutUint16(buf[off:off+2], uint16(rtaLen))
	e.PutUint16(buf[off+2:off+4], unix.IFA_ADDRESS)
	copy(buf[off+4:off+20], ip[:])

	return netlinkRequest(unix.NETLINK_ROUTE, buf)
}

// addRoute4Default adds a default IPv4 route via the named interface.
func addRoute4Default(name string) error {
	ifindex, err := getIfindex(name)
	if err != nil {
		return err
	}

	hdrLen := unix.SizeofNlMsghdr
	rtmLen := 12
	rtaLen := 4 + 4

	totalLen := hdrLen + rtmLen + rtaLen
	buf := make([]byte, totalLen)
	e := binary.NativeEndian

	e.PutUint32(buf[0:4], uint32(totalLen))
	e.PutUint16(buf[4:6], unix.RTM_NEWROUTE)
	e.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE)
	e.PutUint32(buf[8:12], 1)
	e.PutUint32(buf[12:16], 0)

	// struct rtmsg (12 bytes): family, dst_len, src_len, tos,
	// table, protocol, scope, type, flags(u32).
	// flags (off+8..off+11) left zero via zero-initialized buffer.
	off := hdrLen
	buf[off+0] = unix.AF_INET
	buf[off+1] = 0
	buf[off+2] = 0
	buf[off+3] = 0
	buf[off+4] = unix.RT_TABLE_MAIN
	buf[off+5] = unix.RTPROT_BOOT
	buf[off+6] = unix.RT_SCOPE_UNIVERSE
	buf[off+7] = unix.RTN_UNICAST

	off += rtmLen
	e.PutUint16(buf[off:off+2], uint16(rtaLen))
	e.PutUint16(buf[off+2:off+4], unix.RTA_OIF)
	e.PutUint32(buf[off+4:off+8], uint32(ifindex))

	return netlinkRequest(unix.NETLINK_ROUTE, buf)
}

// addRoute6Default adds a default IPv6 route via the named interface.
func addRoute6Default(name string) error {
	ifindex, err := getIfindex(name)
	if err != nil {
		return err
	}

	hdrLen := unix.SizeofNlMsghdr
	rtmLen := 12
	rtaLen := 4 + 4

	totalLen := hdrLen + rtmLen + rtaLen
	buf := make([]byte, totalLen)
	e := binary.NativeEndian

	e.PutUint32(buf[0:4], uint32(totalLen))
	e.PutUint16(buf[4:6], unix.RTM_NEWROUTE)
	e.PutUint16(buf[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE)
	e.PutUint32(buf[8:12], 1)
	e.PutUint32(buf[12:16], 0)

	// struct rtmsg (12 bytes): family, dst_len, src_len, tos,
	// table, protocol, scope, type, flags(u32).
	// flags (off+8..off+11) left zero via zero-initialized buffer.
	off := hdrLen
	buf[off+0] = unix.AF_INET6
	buf[off+1] = 0
	buf[off+2] = 0
	buf[off+3] = 0
	buf[off+4] = unix.RT_TABLE_MAIN
	buf[off+5] = unix.RTPROT_BOOT
	buf[off+6] = unix.RT_SCOPE_UNIVERSE
	buf[off+7] = unix.RTN_UNICAST

	off += rtmLen
	e.PutUint16(buf[off:off+2], uint16(rtaLen))
	e.PutUint16(buf[off+2:off+4], unix.RTA_OIF)
	e.PutUint32(buf[off+4:off+8], uint32(ifindex))

	return netlinkRequest(unix.NETLINK_ROUTE, buf)
}

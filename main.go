package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type user_cap_header struct {
	version uint32
	pid     int
}

type user_cap_data struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

type caps struct {
	hdr  user_cap_header
	data user_cap_data
}

//go:generate stringer -type=CAP
type CAP uint

const (
	CAP_CHOWN CAP = iota
	CAP_DAC_OVERRIDE
	CAP_DAC_READ_SEARCH
	CAP_FOWNER
	CAP_FSETID
	CAP_KILL
	CAP_SETGID
	CAP_SETUID
	CAP_SETPCAP
	CAP_LINX_IMMUTABLE
	CAP_NET_BIND_SERVICE
	CAP_NET_BROADCAST
	CAP_NET_ADMIN
	CAP_NET_RAW
	CAP_IPC_LOCK
	CAP_IPC_OWNER
	CAP_SYS_MODULE
	CAP_SYS_RAWIO
	CAP_SYS_CHROOT
	CAP_SYS_PTRACE
	CAP_SYS_PACCT
	CAP_SYS_ADMIN
	CAP_SYS_BOOT
	CAP_SYS_NICE
	CAP_SYS_RESOURCE
	CAP_SYS_TIME
	CAP_SYS_TTY_CONFIG
	CAP_MKNOD
	CAP_LEASE
	CAP_AUDIT_WRITE
	CAP_AUDIT_CONTROL
	CAP_SETFCAP
	CAP_MAC_OVERRIDE
	CAP_MAC_ADMIN
	CAP_SYSLOG
	CAP_WAKE_ALARM
	CAP_BLOCK_SUSPEND
	CAP_AUDIT_READ
	CAP_LAST_CAP = CAP_AUDIT_READ
)

// 1 << 5 == bits in __u32
func capToIndex(cap uint32) uint32 { return (cap) >> 5 }

// mask for indexed __u32
func capToMask(cap uint32) uint32 { return (1 << ((cap) & 31)) }
func main() {
	code, err := realMain()
	if err != nil {
		fmt.Fprint(os.Stderr, errors.Wrap(err, "problem fetching CAPs\n"))
	}
	os.Exit(code)
}

func realMain() (int, error) {
	if len(os.Args) < 2 {
		return 1, errors.New("please specify a pid to check")
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		return 1, err
	}

	c := caps{
		hdr: user_cap_header{
			pid: pid,
		},
	}

	if _, _, errno := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&c.hdr)), uintptr(unsafe.Pointer(nil)), 0); errno != 0 {
		return int(errno), os.NewSyscallError("capget", errors.New(unix.ErrnoName(errno)))
	}

	if _, _, errno := syscall.Syscall(unix.SYS_CAPGET, uintptr(unsafe.Pointer(&c.hdr)), uintptr(unsafe.Pointer(&c.data)), 0); errno != 0 {
		fmt.Println("cap : %#v", c)

		return int(errno), os.NewSyscallError("capget", errors.New(unix.ErrnoName(errno)))
	}

	fmt.Println("cap", c)

	return 0, nil
}

func checkCap(capSet uint32, cap CAP) (capName string, active bool) {
	active = (capSet & 1 << uint(CAP_SYS_TIME)) != 0

	return CAP.String(), active
}

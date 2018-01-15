// +build linux

// Package sys provides access to the Get Child and Set Child prctl flags.
// See http://man7.org/linux/man-pages/man2/prctl.2.html
package sys

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// GetSubreaper returns the subreaper setting for the calling process
func GetSubreaper() (int, error) {
	var i uintptr
	// PR_GET_CHILD_SUBREAPER allows retrieving the current child
	// subreaper.
	// Returns the "child subreaper" setting of the caller, in the
	// location pointed to by (int *) arg2.
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&i)), 0, 0, 0); err != nil {
		return -1, err
	}
	return int(i), nil
}

// SetSubreaper sets the value i as the subreaper setting for the calling process
func SetSubreaper(i int) error {
	// PR_SET_CHILD_SUBREAPER allows setting the child subreaper.
	// If arg2 is nonzero, set the "child subreaper" attribute of the
	// calling process; if arg2 is zero, unset the attribute.  When a
	// process is marked as a child subreaper, all of the children
	// that it creates, and their descendants, will be marked as
	// having a subreaper.  In effect, a subreaper fulfills the role
	// of init(1) for its descendant processes.  Upon termination of
	// a process that is orphaned (i.e., its immediate parent has
	// already terminated) and marked as having a subreaper, the
	// nearest still living ancestor subreaper will receive a SIGCHLD
	// signal and be able to wait(2) on the process to discover its
	// termination status.
	// 当i不为0时，本进程就会设置为"child subreaper"，并且本进程的所有子进程以及
	// 由此衍生的所有进程都会被标记为有一个subreaper
	// 事实上，subreaper对于由它衍生的进程其实扮演了init进程的角色
	// 当孤儿进程结束的时候，离它最近的subreaper就会收到SIGCHLD信号，并且等待获取该进程的状态
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(i), 0, 0, 0)
}

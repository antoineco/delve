package native

import (
	"debug/elf"
	"syscall"
	"unsafe"

	sys "golang.org/x/sys/unix"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/linutil"
)

const (
	_ARM_GREGS_SIZE  = 18 * 4
	_ARM_FPREGS_SIZE = 32*8 /*fpregs*/ + 4 /*fpscr*/
	_NT_ARM_TLS      = 0x401               // used in PTRACE_GETREGSET on ARM to retrieve the value of TPIDR_EL0, see source/include/uapi/linux/elf.h and source/arch/arm/kernel/ptrace.c
)

func ptraceGetGRegs(pid int, regs *linutil.ARMPtraceRegs) (err error) {
	iov := sys.Iovec{Base: (*byte)(unsafe.Pointer(regs)), Len: _ARM_GREGS_SIZE}
	_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETREGSET, uintptr(pid), uintptr(elf.NT_PRSTATUS), uintptr(unsafe.Pointer(&iov)), 0, 0)
	if err == syscall.Errno(0) {
		err = nil
	}
	return
}

func ptraceGetTpidr_el0(pid int, tpidr_el0 *uint64) (err error) {
	iov := sys.Iovec{Base: (*byte)(unsafe.Pointer(tpidr_el0)), Len: uint32(unsafe.Sizeof(*tpidr_el0))}
	_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETREGSET, uintptr(pid), uintptr(_NT_ARM_TLS), uintptr(unsafe.Pointer(&iov)), 0, 0)
	if err == syscall.Errno(0) {
		err = nil
	}
	return
}

func ptraceSetGRegs(pid int, regs *linutil.ARMPtraceRegs) (err error) {
	iov := sys.Iovec{Base: (*byte)(unsafe.Pointer(regs)), Len: _ARM_GREGS_SIZE}
	_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_SETREGSET, uintptr(pid), uintptr(elf.NT_PRSTATUS), uintptr(unsafe.Pointer(&iov)), 0, 0)
	if err == syscall.Errno(0) {
		err = nil
	}
	return
}

// ptraceGetFpRegset returns floating point registers of the specified thread
// using PTRACE.
func ptraceGetFpRegset(tid int) (fpregset []byte, err error) {
	var arm_fpregs [_ARM_FPREGS_SIZE]byte
	iov := sys.Iovec{Base: &arm_fpregs[0], Len: _ARM_FPREGS_SIZE}
	_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETREGSET, uintptr(tid), uintptr(elf.NT_FPREGSET), uintptr(unsafe.Pointer(&iov)), 0, 0)
	if err != syscall.Errno(0) {
		if err == syscall.ENODEV {
			err = nil
		}
		return
	} else {
		err = nil
	}

	fpregset = arm_fpregs[:iov.Len-8]
	return fpregset, err
}

// setPC sets PC to the value specified by 'pc'.
func (thread *nativeThread) setPC(pc uint64) error {
	ir, err := registers(thread)
	if err != nil {
		return err
	}
	r := ir.(*linutil.ARMRegisters)
	r.Regs.Uregs[regnum.ARM_PC] = uint32(pc)
	thread.dbp.execPtraceFunc(func() { err = ptraceSetGRegs(thread.ID, r.Regs) })
	return err
}

func (thread *nativeThread) SetReg(regNum uint64, reg *op.DwarfRegister) error {
	ir, err := registers(thread)
	if err != nil {
		return err
	}
	r := ir.(*linutil.ARMRegisters)
	fpchanged, err := r.SetReg(regNum, reg)
	if err != nil {
		return err
	}

	thread.dbp.execPtraceFunc(func() {
		err = ptraceSetGRegs(thread.ID, r.Regs)
		if err != syscall.Errno(0) && err != nil {
			return
		}
		if fpchanged && r.Fpregset != nil {
			iov := sys.Iovec{Base: &r.Fpregset[0], Len: uint32(len(r.Fpregset))}
			_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_SETREGSET, uintptr(thread.ID), uintptr(elf.NT_FPREGSET), uintptr(unsafe.Pointer(&iov)), 0, 0)
		}
	})
	if err == syscall.Errno(0) {
		err = nil
	}
	return err
}

func registers(thread *nativeThread) (proc.Registers, error) {
	var (
		regs linutil.ARMPtraceRegs
		err  error
	)
	thread.dbp.execPtraceFunc(func() { err = ptraceGetGRegs(thread.ID, &regs) })
	if err != nil {
		return nil, err
	}
	var tpidr_el0 uint64
	if thread.dbp.iscgo {
		thread.dbp.execPtraceFunc(func() { err = ptraceGetTpidr_el0(thread.ID, &tpidr_el0) })
		if err != nil {
			return nil, err
		}
	}
	r := linutil.NewARMRegisters(&regs, thread.dbp.iscgo, tpidr_el0, func(r *linutil.ARMRegisters) error {
		var floatLoadError error
		r.Fpregs, r.Fpregset, floatLoadError = thread.fpRegisters()
		return floatLoadError
	})
	return r, nil
}

package native

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math/bits"
	"syscall"
	"unsafe"

	"golang.org/x/arch/arm/armasm"
	sys "golang.org/x/sys/unix"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/proc/linutil"
)

func (thread *nativeThread) fpRegisters() ([]proc.Register, []byte, error) {
	var err error
	var arm_fpregs linutil.ARMPtraceFpRegs
	thread.dbp.execPtraceFunc(func() { arm_fpregs.Sregs, err = ptraceGetFpRegset(thread.ID) })
	fpregs := arm_fpregs.Decode()
	if err != nil {
		err = fmt.Errorf("could not get floating point registers: %v", err.Error())
	}
	return fpregs, arm_fpregs.Sregs, err
}

func (t *nativeThread) restoreRegisters(savedRegs proc.Registers) error {
	sr := savedRegs.(*linutil.ARMRegisters)

	var restoreRegistersErr error
	t.dbp.execPtraceFunc(func() {
		restoreRegistersErr = ptraceSetGRegs(t.ID, sr.Regs)
		if restoreRegistersErr != syscall.Errno(0) && restoreRegistersErr != nil {
			return
		}
		if sr.Fpregset != nil {
			iov := sys.Iovec{Base: &sr.Fpregset[0], Len: uint32(len(sr.Fpregset))}
			_, _, restoreRegistersErr = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_SETREGSET, uintptr(t.ID), uintptr(elf.NT_FPREGSET), uintptr(unsafe.Pointer(&iov)), 0, 0)
		}
	})
	if restoreRegistersErr == syscall.Errno(0) {
		restoreRegistersErr = nil
	}
	return restoreRegistersErr
}

// resolvePC is used to resolve next PC for current instruction.
func (t *nativeThread) resolvePC(savedRegs proc.Registers) ([]uint64, error) {
	regs := savedRegs.(*linutil.ARMRegisters)
	nextInstLen := t.BinInfo().Arch.MaxInstructionLength()
	nextInstBytes := make([]byte, nextInstLen)
	var err error

	t.dbp.execPtraceFunc(func() {
		_, err = sys.PtracePeekData(t.ID, uintptr(regs.PC()), nextInstBytes)
	})
	if err != nil {
		return nil, err
	}

	nextPCs := []uint64{regs.PC() + uint64(nextInstLen)}
	if bytes.Equal(nextInstBytes, t.BinInfo().Arch.BreakpointInstruction()) {
		return nextPCs, nil
	}

	nextInst, err := armasm.Decode(nextInstBytes, armasm.ModeARM)
	if err != nil {
		return nil, err
	}
	switch nextInst.Op {
	case armasm.BL, armasm.BLX, armasm.B, armasm.BX:
		switch arg := nextInst.Args[0].(type) {
		case armasm.Imm:
			nextPCs = append(nextPCs, uint64(arg))
		case armasm.Reg:
			pc, err := regs.GetReg(arg)
			if err != nil {
				return nil, err
			}
			nextPCs = append(nextPCs, pc)
		case armasm.PCRel:
			// In ARM code, the value of the PC is the address of the current instruction plus 8 bytes.
			// https://developer.arm.com/documentation/dui0473/m/symbols--literals--expressions--and-operators/register-relative-and-pc-relative-expressions
			nextPCs = append(nextPCs, regs.PC()+uint64(arg)+8)
		}

	case armasm.POP:
		if regList, ok := nextInst.Args[0].(armasm.RegList); ok && (regList&(1<<uint(armasm.PC)) != 0) {
			pc, err := regs.GetReg(armasm.SP)
			if err != nil {
				return nil, err
			}
			for i := 0; i < int(armasm.PC); i++ {
				if regList&(1<<uint(i)) != 0 {
					pc += uint64(nextInstLen)
				}
			}
			pcMem := make([]byte, nextInstLen)
			t.dbp.execPtraceFunc(func() {
				_, err = sys.PtracePeekData(t.ID, uintptr(pc), pcMem)
			})
			if err != nil {
				return nil, err
			}
			nextPCs = append(nextPCs, uint64(binary.LittleEndian.Uint32(pcMem)))
		}

	case armasm.LDR:
		// first arg is PC register
		if reg, ok := nextInst.Args[0].(armasm.Reg); ok && reg == armasm.PC {
			switch arg := nextInst.Args[1].(type) {
			case armasm.Mem:
				pc, err := regs.GetReg(arg.Base)
				if err != nil {
					return nil, err
				}
				if arg.Mode == armasm.AddrOffset || arg.Mode == armasm.AddrPreIndex {
					if arg.Sign != 0 {
						idx, err := regs.GetReg(arg.Index)
						if err != nil {
							return nil, err
						}
						if arg.Shift != armasm.ShiftLeft || arg.Count != 0 {
							switch arg.Shift {
							case armasm.ShiftLeft:
								idx <<= arg.Count
							case armasm.ShiftRight, armasm.ShiftRightSigned:
								idx >>= arg.Count
							case armasm.RotateRight, armasm.RotateRightExt:
								idx = bits.RotateLeft64(idx, int(-arg.Count))
							}
						}
						if arg.Sign < 0 {
							pc -= idx
						} else {
							pc += idx
						}
					} else {
						pc = uint64(int64(pc) + int64(arg.Offset))
					}
				}
				pcMem := make([]byte, nextInstLen)
				t.dbp.execPtraceFunc(func() {
					_, err = sys.PtracePeekData(t.ID, uintptr(pc), pcMem)
				})
				if err != nil {
					return nil, err
				}
				nextPCs = append(nextPCs, uint64(binary.LittleEndian.Uint32(pcMem)))
			}
		}

	case armasm.MOV, armasm.ADD:
		// first arg is PC register
		if reg, ok := nextInst.Args[0].(armasm.Reg); ok && reg == armasm.PC {
			var pc uint64
			for _, argRaw := range nextInst.Args[1:] {
				switch arg := argRaw.(type) {
				case armasm.Imm:
					pc += uint64(arg)
				case armasm.Reg:
					regVal, err := regs.GetReg(arg)
					if err != nil {
						return nil, err
					}
					pc += regVal
				}
			}
			nextPCs = append(nextPCs, pc)
		}
	}

	return nextPCs, nil
}

// ARM doesn't have ptrace singlestep support, so use breakpoint to emulate it.
func (procgrp *processGroup) singleStep(t *nativeThread) (err error) {
	regs, err := t.Registers()
	if err != nil {
		return err
	}
	nextPCs, err := t.resolvePC(regs)
	if err != nil {
		return err
	}
	originalDataSet := make(map[uintptr][]byte)

	// Do in batch, first set breakpoint, then continue.
	t.dbp.execPtraceFunc(func() {
		breakpointInstr := t.BinInfo().Arch.BreakpointInstruction()
		readWriteMem := func(i int, addr uintptr, instr []byte) error {
			originalData := make([]byte, len(breakpointInstr))
			_, err = sys.PtracePeekData(t.ID, addr, originalData)
			if err != nil {
				return err
			}
			_, err = sys.PtracePokeData(t.ID, addr, instr)
			if err != nil {
				return err
			}
			// Everything is ok, store originalData
			originalDataSet[addr] = originalData
			return nil
		}
		for i, nextPc := range nextPCs {
			err = readWriteMem(i, uintptr(nextPc), breakpointInstr)
			if err != nil {
				return
			}
		}
	})
	// Make sure we restore before return.
	defer func() {
		// Update err.
		t.dbp.execPtraceFunc(func() {
			for addr, originalData := range originalDataSet {
				if originalData != nil {
					_, err = sys.PtracePokeData(t.ID, addr, originalData)
				}
			}
		})
	}()
	if err != nil {
		return err
	}
	for {
		sig := 0
		t.dbp.execPtraceFunc(func() {
			err = ptraceCont(t.ID, sig)
		})
		if err != nil {
			return err
		}
		// To be able to catch process exit, we can only use wait instead of waitFast.
		wpid, status, err := t.dbp.wait(t.ID, 0)
		if err != nil {
			return err
		}
		if (status == nil || status.Exited()) && wpid == t.dbp.pid {
			t.dbp.postExit()
			rs := 0
			if status != nil {
				rs = status.ExitStatus()
			}
			return proc.ErrProcessExited{Pid: t.dbp.pid, Status: rs}
		}
		if wpid == t.ID {
			sig = 0
			switch s := status.StopSignal(); s {
			case sys.SIGTRAP:
				return nil
			case sys.SIGSTOP:
				// delayed SIGSTOP, ignore it
			case sys.SIGILL, sys.SIGBUS, sys.SIGFPE, sys.SIGSEGV, sys.SIGSTKFLT:
				// propagate signals that can have been caused by the current instruction
				sig = int(s)
			default:
				// delay propagation of all other signals
				t.os.delayedSignal = int(s)
			}
		}
	}
}

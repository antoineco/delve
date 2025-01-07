package linutil

import (
	"fmt"

	"golang.org/x/arch/arm/armasm"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
	"github.com/go-delve/delve/pkg/proc"
)

// ARMRegisters is a wrapper for sys.PtraceRegs.
type ARMRegisters struct {
	Regs      *ARMPtraceRegs // general-purpose registers
	iscgo     bool
	tpidr_el0 uint64
	Fpregs    []proc.Register // Formatted floating point registers
	Fpregset  []byte          // holding all floating point register values

	loadFpRegs func(*ARMRegisters) error
}

func NewARMRegisters(regs *ARMPtraceRegs, iscgo bool, tpidr_el0 uint64, loadFpRegs func(*ARMRegisters) error) *ARMRegisters {
	return &ARMRegisters{Regs: regs, iscgo: iscgo, tpidr_el0: tpidr_el0, loadFpRegs: loadFpRegs}
}

// ARMPtraceRegs is the struct used by the linux kernel to return the
// general purpose registers for ARM CPUs.
// copy from sys/unix/ztypes_linux_arm.go:516
type ARMPtraceRegs struct {
	Uregs [18]uint32
}

// Slice returns the registers as a list of (name, value) pairs.
func (r *ARMRegisters) Slice(floatingPoint bool) ([]proc.Register, error) {
	var regs = []struct {
		k string
		v uint32
	}{
		{"R0", r.Regs.Uregs[0]},
		{"R1", r.Regs.Uregs[1]},
		{"R2", r.Regs.Uregs[2]},
		{"R3", r.Regs.Uregs[3]},
		{"R4", r.Regs.Uregs[4]},
		{"R5", r.Regs.Uregs[5]},
		{"R6", r.Regs.Uregs[6]},
		{"R7", r.Regs.Uregs[7]},
		{"R8", r.Regs.Uregs[8]},
		{"R9", r.Regs.Uregs[9]},
		{"R10", r.Regs.Uregs[10]},
		{"BP", r.Regs.Uregs[11]},
		{"R12", r.Regs.Uregs[12]},
		{"SP", r.Regs.Uregs[13]},
		{"LR", r.Regs.Uregs[14]},
		{"PC", r.Regs.Uregs[15]},
		{"CPSR", r.Regs.Uregs[16]},
		{"ORIG_R0", r.Regs.Uregs[17]},
	}
	out := make([]proc.Register, 0, len(regs)+len(r.Fpregs))
	for _, reg := range regs {
		out = proc.AppendUint64Register(out, reg.k, uint64(reg.v))
	}
	var floatLoadError error
	if floatingPoint {
		if r.loadFpRegs != nil {
			floatLoadError = r.loadFpRegs(r)
			r.loadFpRegs = nil
		}
		out = append(out, r.Fpregs...)
	}
	return out, floatLoadError
}

// PC returns the value of RIP register.
func (r *ARMRegisters) PC() uint64 {
	return uint64(r.Regs.Uregs[regnum.ARM_PC])
}

// SP returns the value of RSP register.
func (r *ARMRegisters) SP() uint64 {
	return uint64(r.Regs.Uregs[regnum.ARM_SP])
}

func (r *ARMRegisters) BP() uint64 {
	return uint64(r.Regs.Uregs[regnum.ARM_BP])
}

// TLS returns the address of the thread local storage memory segment.
func (r *ARMRegisters) TLS() uint64 {
	if !r.iscgo {
		return 0
	}
	return r.tpidr_el0
}

// GAddr returns the address of the G variable if it is known, 0 and false
// otherwise.
func (r *ARMRegisters) GAddr() (uint64, bool) {
	return uint64(r.Regs.Uregs[10]), true
}

// LR returns the link register.
func (r *ARMRegisters) LR() uint64 {
	return uint64(r.Regs.Uregs[regnum.ARM_LR])
}

// Copy returns a copy of these registers that is guaranteed not to change.
func (r *ARMRegisters) Copy() (proc.Registers, error) {
	if r.loadFpRegs != nil {
		err := r.loadFpRegs(r)
		r.loadFpRegs = nil
		if err != nil {
			return nil, err
		}
	}
	var rr ARMRegisters
	rr.Regs = &ARMPtraceRegs{}
	*(rr.Regs) = *(r.Regs)
	if r.Fpregs != nil {
		rr.Fpregs = make([]proc.Register, len(r.Fpregs))
		copy(rr.Fpregs, r.Fpregs)
	}
	if r.Fpregset != nil {
		rr.Fpregset = make([]byte, len(r.Fpregset))
		copy(rr.Fpregset, r.Fpregset)
	}
	return &rr, nil
}

func (r *ARMRegisters) GetReg(regNum armasm.Reg) (uint64, error) {
	if regNum <= armasm.R15 {
		return uint64(r.Regs.Uregs[regNum-armasm.R0]), nil
	}
	return 0, proc.ErrUnknownRegister
}

func (r *ARMRegisters) SetReg(regNum uint64, reg *op.DwarfRegister) (fpchanged bool, err error) {
	switch regNum {
	case regnum.ARM_PC:
		r.Regs.Uregs[regnum.ARM_PC] = uint32(reg.Uint64Val)
		return false, nil
	case regnum.ARM_SP:
		r.Regs.Uregs[regnum.ARM_SP] = uint32(reg.Uint64Val)
		return false, nil
	default:
		switch {
		case regNum >= regnum.ARM_R0 && regNum <= regnum.ARM_R0+15:
			r.Regs.Uregs[regNum-regnum.ARM_R0] = uint32(reg.Uint64Val)
			return false, nil

		case regNum >= regnum.ARM_S0 && regNum <= regnum.ARM_S0+31:
			if r.loadFpRegs != nil {
				err := r.loadFpRegs(r)
				r.loadFpRegs = nil
				if err != nil {
					return false, err
				}
			}

			i := regNum - regnum.ARM_S0
			reg.FillBytes()
			copy(r.Fpregset[16*i:], reg.Bytes)
			return true, nil

		default:
			return false, fmt.Errorf("changing register %d not implemented", regNum)
		}
	}
}

type ARMPtraceFpRegs struct {
	Sregs []byte
	Fpsr  uint32
	Fpcr  uint32
}

const _ARM32_FP_REGS_LENGTH = 32

func (fpregs *ARMPtraceFpRegs) Decode() (regs []proc.Register) {
	// According to arch/arm/include/asm/ptrace.h, the length of fpregs is 8.
	for i := 0; i < len(fpregs.Sregs); i += 8 {
		regs = proc.AppendBytesRegister(regs, fmt.Sprintf("S%d", i/8), fpregs.Sregs[i:i+8])
	}
	return
}

func (fpregs *ARMPtraceFpRegs) Byte() []byte {
	fpregs.Sregs = make([]byte, _ARM32_FP_REGS_LENGTH)
	return fpregs.Sregs[:]
}

package proc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"

	"github.com/go-delve/delve/pkg/dwarf/frame"
	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"
)

// UND pseudo-instruction
// https://developer.arm.com/documentation/101754/0623/armasm-Legacy-Assembler-Reference/armasm-Specific-A32-and-T32-Instruction-Set-Features/UND-pseudo-instruction
var armBreakInstruction = []byte{0xf0, 0x01, 0xf0, 0xe7}

// ARMArch returns an initialized ARM
// struct.
func ARMArch(goos string) *Arch {
	return &Arch{
		Name:                             "arm",
		ptrSize:                          4,
		maxInstructionLength:             4,
		breakpointInstruction:            armBreakInstruction,
		breakInstrMovesPC:                false,
		derefTLS:                         false,
		prologues:                        prologuesARM,
		fixFrameUnwindContext:            armFixFrameUnwindContext,
		switchStack:                      armSwitchStack,
		regSize:                          armRegSize,
		RegistersToDwarfRegisters:        armRegistersToDwarfRegisters,
		addrAndStackRegsToDwarfRegisters: armAddrAndStackRegsToDwarfRegisters,
		DwarfRegisterToString:            armDwarfRegisterToString,
		inhibitStepInto:                  func(*BinaryInfo, uint64) bool { return false },
		asmDecode:                        armAsmDecode,
		usesLR:                           true,
		PCRegNum:                         regnum.ARM_PC,
		SPRegNum:                         regnum.ARM_SP,
		ContextRegNum:                    regnum.ARM_R0 + 7,
		LRRegNum:                         regnum.ARM_LR,
		asmRegisters:                     armAsmRegisters,
		RegisterNameToDwarf:              nameToDwarfFunc(regnum.ARMNameToDwarf),
		RegnumToString:                   regnum.ARMToName,
		debugCallMinStackSize:            288,
		maxRegArgBytes:                   16*4 + 16*4, // 16 int argument registers plus 16 float argument registers
		argumentRegs:                     []int{regnum.ARM_R0, regnum.ARM_R0 + 1, regnum.ARM_R0 + 2},
	}
}

func armFixFrameUnwindContext(fctxt *frame.FrameContext, pc uint64, bi *BinaryInfo) *frame.FrameContext {
	a := bi.Arch
	if a.sigreturnfn == nil {
		a.sigreturnfn = bi.lookupOneFunc("runtime.sigreturn")
	}

	if fctxt == nil || (a.sigreturnfn != nil && pc >= a.sigreturnfn.Entry && pc < a.sigreturnfn.End) {
		// When there's no frame descriptor entry use BP (the frame pointer) instead
		// - return register is [bp + a.PtrSize()] (i.e. [cfa-a.PtrSize()])
		// - cfa is bp + a.PtrSize()*2
		// - bp is [bp] (i.e. [cfa-a.PtrSize()*2])
		// - sp is cfa

		// When the signal handler runs it will move the execution to the signal
		// handling stack (installed using the sigaltstack system call).
		// This isn't a proper stack switch: the pointer to g in TLS will still
		// refer to whatever g was executing on that thread before the signal was
		// received.
		// Since go did not execute a stack switch the previous value of sp, pc
		// and bp is not saved inside g.sched, as it normally would.
		// The only way to recover is to either read sp/pc from the signal context
		// parameter (the ucontext_t* parameter) or to unconditionally follow the
		// frame pointer when we get to runtime.sigreturn (which is what we do
		// here).

		return &frame.FrameContext{
			RetAddrReg: regnum.ARM_PC,
			Regs: map[uint64]frame.DWRule{
				regnum.ARM_PC: {
					Rule:   frame.RuleOffset,
					Offset: int64(-a.PtrSize()),
				},
				regnum.ARM_BP: {
					Rule:   frame.RuleOffset,
					Offset: int64(-2 * a.PtrSize()),
				},
				regnum.ARM_SP: {
					Rule:   frame.RuleValOffset,
					Offset: 0,
				},
			},
			CFA: frame.DWRule{
				Rule:   frame.RuleCFA,
				Reg:    regnum.ARM_BP,
				Offset: int64(2 * a.PtrSize()),
			},
		}
	}

	if a.crosscall2fn == nil {
		a.crosscall2fn = bi.lookupOneFunc("crosscall2")
	}

	if a.crosscall2fn != nil && pc >= a.crosscall2fn.Entry && pc < a.crosscall2fn.End {
		rule := fctxt.CFA
		if rule.Offset == crosscall2SPOffsetBad {
			rule.Offset += crosscall2SPOffset
		}
		fctxt.CFA = rule
	}

	// We assume that RBP is the frame pointer, and we want to keep it updated,
	// so that we can use it to unwind the stack even when we encounter frames
	// without descriptor entries.
	// If there isn't a rule already we emit one.
	if fctxt.Regs[regnum.ARM_BP].Rule == frame.RuleUndefined {
		fctxt.Regs[regnum.ARM_BP] = frame.DWRule{
			Rule:   frame.RuleFramePointer,
			Reg:    regnum.ARM_BP,
			Offset: 0,
		}
	}
	if fctxt.Regs[regnum.ARM_LR].Rule == frame.RuleUndefined {
		fctxt.Regs[regnum.ARM_LR] = frame.DWRule{
			Rule:   frame.RuleRegister,
			Reg:    regnum.ARM_LR,
			Offset: 0,
		}
	}

	return fctxt
}

const armcgocallSPOffsetSaveSlot = 0x4
const armPrevG0schedSPOffsetSaveSlot = 0x8

func armSwitchStack(it *stackIterator, callFrameRegs *op.DwarfRegisters) bool {
	linux := runtime.GOOS == "linux"
	if it.frame.Current.Fn == nil {
		if it.systemstack && it.g != nil && it.top {
			if err := it.switchToGoroutineStack(); err != nil {
				it.err = err
				return false
			}
			return true
		}
		return false
	}
	switch it.frame.Current.Fn.Name {
	case "runtime.cgocallback_gofunc", "runtime.cgocallback":
		if linux {
			// For a detailed description of how this works read the long comment at
			// the start of $GOROOT/src/runtime/cgocall.go and the source code of
			// runtime.cgocallback_gofunc in $GOROOT/src/runtime/asm_arm.s
			//
			// When a C function calls back into go it will eventually call into
			// runtime.cgocallback_gofunc which is the function that does the stack
			// switch from the system stack back into the goroutine stack
			// Since we are going backwards on the stack here we see the transition
			// as goroutine stack -> system stack.
			if it.top || it.systemstack {
				return false
			}

			it.loadG0SchedSP()
			if it.g0_sched_sp <= 0 {
				return false
			}
			// Entering the system stack.
			it.regs.Reg(callFrameRegs.SPRegNum).Uint64Val = it.g0_sched_sp
			// Reads the previous value of g0.sched.sp that runtime.cgocallback_gofunc saved on the stack.
			it.g0_sched_sp, _ = readUintRaw(it.mem, it.regs.SP()+armPrevG0schedSPOffsetSaveSlot, int64(it.bi.Arch.PtrSize()))
			it.top = false
			callFrameRegs, ret, retaddr := it.advanceRegs()
			frameOnSystemStack := it.newStackframe(ret, retaddr)
			it.pc = frameOnSystemStack.Ret
			it.regs = callFrameRegs
			it.systemstack = true

			return true
		}

	case "runtime.asmcgocall":
		if linux {
			if it.top || !it.systemstack {
				return false
			}

			// This function is called by a goroutine to execute a C function and
			// switches from the goroutine stack to the system stack.
			// Since we are unwinding the stack from callee to caller we have to switch
			// from the system stack to the goroutine stack.
			off, _ := readIntRaw(it.mem, it.regs.SP()+armcgocallSPOffsetSaveSlot,
				int64(it.bi.Arch.PtrSize()))
			oldsp := it.regs.SP()
			newsp := uint64(int64(it.stackhi) - off)

			it.regs.Reg(it.regs.SPRegNum).Uint64Val = uint64(int64(newsp))
			// runtime.asmcgocall can also be called from inside the system stack,
			// in that case no stack switch actually happens
			if it.regs.SP() == oldsp {
				return false
			}

			it.top = false
			it.systemstack = false
			// The return value is stored in the LR register which is saved at 24(SP).
			addrret := uint64(int64(it.regs.SP()) + int64(it.bi.Arch.PtrSize()*3))
			it.frame.Ret, _ = readUintRaw(it.mem, addrret, int64(it.bi.Arch.PtrSize()))
			it.pc = it.frame.Ret

			return true
		}

	case "runtime.goexit", "runtime.rt0_go":
		// Look for "top of stack" functions.
		it.atend = true
		return true

	case "runtime.mcall":
		if it.systemstack && it.g != nil {
			if err := it.switchToGoroutineStack(); err != nil {
				it.err = err
				return false
			}
			return true
		}
		it.atend = true
		return true

	case "crosscall2":
		// The offsets get from runtime/cgo/asm_arm.s:24
		newsp, _ := readUintRaw(it.mem, it.regs.SP()+8*9+4*14, int64(it.bi.Arch.PtrSize()))
		newbp, _ := readUintRaw(it.mem, it.regs.SP()+4*11, int64(it.bi.Arch.PtrSize()))
		newlr, _ := readUintRaw(it.mem, it.regs.SP()+4*13, int64(it.bi.Arch.PtrSize()))
		if it.regs.Reg(it.regs.BPRegNum) != nil {
			it.regs.Reg(it.regs.BPRegNum).Uint64Val = newbp
		} else {
			reg, _ := it.readRegisterAt(it.regs.BPRegNum, it.regs.SP()+4*11)
			it.regs.AddReg(it.regs.BPRegNum, reg)
		}
		it.regs.Reg(it.regs.LRRegNum).Uint64Val = newlr
		if linux {
			it.regs.Reg(it.regs.SPRegNum).Uint64Val = newbp
		} else {
			it.regs.Reg(it.regs.SPRegNum).Uint64Val = newsp
		}
		it.pc = newlr
		return true
	case "runtime.mstart":
		if linux {
			// Calls to runtime.systemstack will switch to the systemstack then:
			// 1. alter the goroutine stack so that it looks like systemstack_switch
			//    was called
			// 2. alter the system stack so that it looks like the bottom-most frame
			//    belongs to runtime.mstart
			// If we find a runtime.mstart frame on the system stack of a goroutine
			// parked on runtime.systemstack_switch we assume runtime.systemstack was
			// called and continue tracing from the parked position.

			if it.top || !it.systemstack || it.g == nil {
				return false
			}
			if fn := it.bi.PCToFunc(it.g.PC); fn == nil || fn.Name != "runtime.systemstack_switch" {
				return false
			}

			if err := it.switchToGoroutineStack(); err != nil {
				it.err = err
				return false
			}
			return true
		}

	case "runtime.newstack", "runtime.systemstack":
		if it.systemstack && it.g != nil {
			if err := it.switchToGoroutineStack(); err != nil {
				it.err = err
				return false
			}
			return true
		}
	}

	fn := it.bi.PCToFunc(it.frame.Ret)
	if fn == nil {
		return false
	}
	switch fn.Name {
	case "runtime.asmcgocall":
		if !it.systemstack {
			return false
		}

		// This function is called by a goroutine to execute a C function and
		// switches from the goroutine stack to the system stack.
		// Since we are unwinding the stack from callee to caller we have to switch
		// from the system stack to the goroutine stack.
		off, _ := readIntRaw(it.mem, callFrameRegs.SP()+armcgocallSPOffsetSaveSlot, int64(it.bi.Arch.PtrSize()))
		oldsp := callFrameRegs.SP()
		newsp := uint64(int64(it.stackhi) - off)

		// runtime.asmcgocall can also be called from inside the system stack,
		// in that case no stack switch actually happens
		if newsp == oldsp {
			return false
		}
		it.systemstack = false
		callFrameRegs.Reg(callFrameRegs.SPRegNum).Uint64Val = uint64(int64(newsp))
		return false

	case "runtime.cgocallback_gofunc", "runtime.cgocallback":
		// For a detailed description of how this works read the long comment at
		// the start of $GOROOT/src/runtime/cgocall.go and the source code of
		// runtime.cgocallback_gofunc in $GOROOT/src/runtime/asm_arm.s
		//
		// When a C functions calls back into go it will eventually call into
		// runtime.cgocallback_gofunc which is the function that does the stack
		// switch from the system stack back into the goroutine stack
		// Since we are going backwards on the stack here we see the transition
		// as goroutine stack -> system stack.
		if it.systemstack {
			return false
		}

		it.loadG0SchedSP()
		if it.g0_sched_sp <= 0 {
			return false
		}
		// entering the system stack
		callFrameRegs.Reg(callFrameRegs.SPRegNum).Uint64Val = it.g0_sched_sp
		// reads the previous value of g0.sched.sp that runtime.cgocallback_gofunc saved on the stack

		it.g0_sched_sp, _ = readUintRaw(it.mem, callFrameRegs.SP()+prevG0schedSPOffsetSaveSlot, int64(it.bi.Arch.PtrSize()))
		it.systemstack = true
		return false
	}

	return false
}

func armRegSize(regnum uint64) int {
	// fp registers
	if regnum >= 64 && regnum <= 95 {
		return 8
	}

	return 4 // general registers
}

var armNameToDwarf = func() map[string]int {
	r := make(map[string]int)
	for i := 0; i <= 15; i++ {
		r[fmt.Sprintf("r%d", i)] = i
	}
	r["pc"] = int(regnum.ARM_PC)
	r["lr"] = int(regnum.ARM_LR)
	r["sp"] = int(regnum.ARM_SP)
	for i := 0; i <= 31; i++ {
		r[fmt.Sprintf("s%d", i)] = i + 64
	}
	return r
}()

func armRegistersToDwarfRegisters(staticBase uint64, regs Registers) *op.DwarfRegisters {
	dregs := initDwarfRegistersFromSlice(int(regnum.ARMMaxRegNum()), regs, regnum.ARMNameToDwarf)
	dr := op.NewDwarfRegisters(staticBase, dregs, binary.LittleEndian, regnum.ARM_PC, regnum.ARM_SP, regnum.ARM_BP, regnum.ARM_LR)
	dr.SetLoadMoreCallback(loadMoreDwarfRegistersFromSliceFunc(dr, regs, armNameToDwarf))
	return dr
}

func armAddrAndStackRegsToDwarfRegisters(staticBase, pc, sp, bp, lr uint64) op.DwarfRegisters {
	dregs := make([]*op.DwarfRegister, regnum.ARM_PC+1)
	dregs[regnum.ARM_PC] = op.DwarfRegisterFromUint64(pc)
	dregs[regnum.ARM_SP] = op.DwarfRegisterFromUint64(sp)
	dregs[regnum.ARM_BP] = op.DwarfRegisterFromUint64(bp)
	dregs[regnum.ARM_LR] = op.DwarfRegisterFromUint64(lr)

	return *op.NewDwarfRegisters(staticBase, dregs, binary.LittleEndian, regnum.ARM_PC, regnum.ARM_SP, regnum.ARM_BP, regnum.ARM_LR)
}

func armDwarfRegisterToString(i int, reg *op.DwarfRegister) (name string, floatingPoint bool, repr string) {
	name = regnum.ARMToName(uint64(i))

	if reg == nil {
		return name, false, ""
	}

	if reg.Bytes != nil && name[0] == 'S' {
		buf := bytes.NewReader(reg.Bytes)

		var out bytes.Buffer
		var vi [8]uint8
		for i := range vi {
			_ = binary.Read(buf, binary.LittleEndian, &vi[i])
		}
		//D
		fmt.Fprintf(&out, " {\n\tD = {u = {0x%02x%02x%02x%02x%02x%02x%02x%02x},", vi[7], vi[6], vi[5], vi[4], vi[3], vi[2], vi[1], vi[0])
		fmt.Fprintf(&out, " s = {0x%02x%02x%02x%02x%02x%02x%02x%02x}},", vi[7], vi[6], vi[5], vi[4], vi[3], vi[2], vi[1], vi[0])

		//S
		fmt.Fprintf(&out, " \n\tS = {u = {0x%02x%02x%02x%02x,0x%02x%02x%02x%02x},", vi[3], vi[2], vi[1], vi[0], vi[7], vi[6], vi[5], vi[4])
		fmt.Fprintf(&out, " s = {0x%02x%02x%02x%02x,0x%02x%02x%02x%02x}},", vi[3], vi[2], vi[1], vi[0], vi[7], vi[6], vi[5], vi[4])

		//H
		fmt.Fprintf(&out, " \n\tH = {u = {0x%02x%02x,0x%02x%02x,0x%02x%02x,0x%02x%02x},", vi[1], vi[0], vi[3], vi[2], vi[5], vi[4], vi[7], vi[6])
		fmt.Fprintf(&out, " s = {0x%02x%02x,0x%02x%02x,0x%02x%02x,0x%02x%02x}},", vi[1], vi[0], vi[3], vi[2], vi[5], vi[4], vi[7], vi[6])

		//B
		fmt.Fprintf(&out, " \n\tB = {u = {0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x},", vi[0], vi[1], vi[2], vi[3], vi[4], vi[5], vi[6], vi[7])
		fmt.Fprintf(&out, " s = {0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x}},", vi[0], vi[1], vi[2], vi[3], vi[4], vi[5], vi[6], vi[7])

		//Q
		fmt.Fprintf(&out, " \n\tQ = {u = {0x%02x%02x%02x%02x%02x%02x%02x%02x},", vi[7], vi[6], vi[5], vi[4], vi[3], vi[2], vi[1], vi[0])
		fmt.Fprintf(&out, " s = {0x%02x%02x%02x%02x%02x%02x%02x%02x}}\n\t}", vi[7], vi[6], vi[5], vi[4], vi[3], vi[2], vi[1], vi[0])
		return name, true, out.String()
	} else if reg.Bytes == nil || (reg.Bytes != nil && len(reg.Bytes) < 16) {
		return name, false, fmt.Sprintf("%#04x", reg.Uint64Val)
	}
	return name, false, fmt.Sprintf("%#x", reg.Bytes)
}

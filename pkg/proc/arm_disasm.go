package proc

import (
	"bytes"

	"github.com/go-delve/delve/pkg/dwarf/op"
	"github.com/go-delve/delve/pkg/dwarf/regnum"

	"golang.org/x/arch/arm/armasm"
)

func armAsmDecode(asmInst *AsmInstruction, mem []byte, regs *op.DwarfRegisters, _ MemoryReadWriter, bi *BinaryInfo) error {
	asmInst.Size = 4
	asmInst.Bytes = mem[:asmInst.Size]

	if bytes.Equal(asmInst.Bytes, armBreakInstruction) {
		asmInst.Inst = (*armArchInst)(nil)
		asmInst.Kind = HardBreakInstruction
		return nil
	}

	inst, err := armasm.Decode(mem, armasm.ModeARM)
	if err != nil {
		asmInst.Inst = (*armArchInst)(nil)
		return err
	}

	asmInst.Inst = (*armArchInst)(&inst)
	asmInst.Kind = OtherInstruction

	switch inst.Op {
	case armasm.BL, armasm.BLX:
		asmInst.Kind = CallInstruction
	case armasm.B, armasm.BX:
		asmInst.Kind = JmpInstruction
	case armasm.LDR, armasm.ADD, armasm.MOV:
		// first arg is PC register
		if reg, ok := inst.Args[0].(armasm.Reg); ok && reg == armasm.PC {
			asmInst.Kind = RetInstruction
		}
	case armasm.POP:
		// first arg has PC in register list
		if regList, ok := inst.Args[0].(armasm.RegList); ok && (regList&(1<<uint(armasm.PC)) != 0) {
			asmInst.Kind = RetInstruction
		}
	}

	asmInst.DestLoc = resolveCallArgARM(&inst, asmInst.Loc.PC, asmInst.AtPC, regs, bi)

	return nil
}

func resolveCallArgARM(inst *armasm.Inst, instAddr uint64, currentGoroutine bool, regs *op.DwarfRegisters, bininfo *BinaryInfo) *Location {
	switch inst.Op {
	case armasm.BL, armasm.BLX, armasm.B, armasm.BX:
		// ok
	default:
		return nil
	}

	var pc uint64
	var err error

	switch arg := inst.Args[0].(type) {
	case armasm.Imm:
		pc = uint64(arg)
	case armasm.Reg:
		if !currentGoroutine || regs == nil {
			return nil
		}
		pc, err = bininfo.Arch.getAsmRegister(regs, int(arg))
		if err != nil {
			return nil
		}
	case armasm.PCRel:
		// In ARM code, the value of the PC is the address of the current instruction plus 8 bytes.
		// https://developer.arm.com/documentation/dui0473/m/symbols--literals--expressions--and-operators/register-relative-and-pc-relative-expressions
		pc = instAddr + uint64(arg) + 8
	default:
		return nil
	}

	file, line, fn := bininfo.PCToLine(pc)
	if fn == nil {
		return &Location{PC: pc}
	}
	return &Location{PC: pc, File: file, Line: line, Fn: fn}
}

// Possible stacksplit prologues are inserted by stacksplit in
// $GOROOT/src/cmd/internal/obj/arm/obj5.go.
var prologuesARM []opcodeSeq

func init() {
	var tinyStacksplit = opcodeSeq{uint64(armasm.CMP), uint64(armasm.B)}
	var smallStacksplit = opcodeSeq{uint64(armasm.MOVW), uint64(armasm.CMP), uint64(armasm.B)}
	var bigStacksplit = opcodeSeq{uint64(armasm.CMP), uint64(armasm.MOVW_NE), uint64(armasm.SUB_NE), uint64(armasm.MOVW_NE), uint64(armasm.CMP_NE), uint64(armasm.B)}
	var unixGetG = opcodeSeq{uint64(armasm.LDR)}

	prologuesARM = make([]opcodeSeq, 0, 3)
	for _, getG := range []opcodeSeq{unixGetG} {
		for _, stacksplit := range []opcodeSeq{tinyStacksplit, smallStacksplit, bigStacksplit} {
			prologue := make(opcodeSeq, 0, len(getG)+len(stacksplit))
			prologue = append(prologue, getG...)
			prologue = append(prologue, stacksplit...)
			prologuesARM = append(prologuesARM, prologue)
		}
	}
}

type armArchInst armasm.Inst

func (inst *armArchInst) Text(flavour AssemblyFlavour, pc uint64, symLookup func(uint64) (string, uint64)) string {
	if inst == nil {
		return "?"
	}

	var text string

	switch flavour {
	case GNUFlavour:
		text = armasm.GNUSyntax(armasm.Inst(*inst))
	default:
		text = armasm.GoSyntax(armasm.Inst(*inst), pc, symLookup, nil)
	}

	return text
}

func (inst *armArchInst) OpcodeEquals(op uint64) bool {
	if inst == nil {
		return false
	}
	return uint64(inst.Op) == op
}

var armAsmRegisters = func() map[int]asmRegister {
	r := make(map[int]asmRegister)
	for i := armasm.R0; i <= armasm.R15; i++ {
		r[int(i)] = asmRegister{regnum.ARM_R0 + uint64(i-armasm.R0), 0, 0}
	}
	return r
}()

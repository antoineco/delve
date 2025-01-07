package regnum

import (
	"fmt"
)

// The mapping between hardware registers and DWARF registers is specified
// in the DWARF for the Arm® Architecture document, Section 4, Table 1.
// https://github.com/ARM-software/abi-aa/blob/main/aadwarf32/aadwarf32.rst#arm-specific-dwarf-definitions

const (
	ARM_R0         = 0  // R0 through R15 follow
	ARM_BP         = 11 // also R11
	ARM_SP         = 13 // also R13
	ARM_LR         = 14 // also R14
	ARM_PC         = 15 // also R15
	ARM_S0         = 64 // S0 through S31 follow
	_ARM_MaxRegNum = ARM_S0 + 31
)

func ARMToName(num uint64) string {
	switch {
	case num <= 15:
		return fmt.Sprintf("R%d", num)
	case num >= ARM_S0 && num <= ARM_S0+31:
		return fmt.Sprintf("S%d", num-ARM_S0)
	default:
		return fmt.Sprintf("unknown%d", num)
	}
}

func ARMMaxRegNum() uint64 {
	return _ARM_MaxRegNum
}

var ARMNameToDwarf = func() map[string]int {
	r := make(map[string]int)
	for i := 0; i <= 15; i++ {
		r[fmt.Sprintf("r%d", i)] = ARM_R0 + i
	}
	r["fp"] = 11
	r["sp"] = 13
	r["lr"] = 14
	r["pc"] = 15

	for i := 0; i <= 31; i++ {
		r[fmt.Sprintf("s%d", i)] = ARM_S0 + i
	}

	return r
}()

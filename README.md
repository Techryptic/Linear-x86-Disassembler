# [Linear-x86-Disassembler](http://anthonys.io/cyber-defense-competition-writeup-as-blue-team-leader/): 
This is a x86 disassembler that implements linear sweep algorithms.

Created by [@Tech](https://twitter.com/Tech) || [anthonys.io](http://anthonys.io)

## 
My Disassembler attempts to parse arbitrary binary input into x86 assembly code.
* Uses Linear Sweep algorithm to disassemble an arbitrary binary file:
* Only the following mnemonics are implemented:
add nop and not call or cmp pop dec push idiv repne cmpsd imul retf inc retn
jmp sal jz/jnz sar lea sbb mov shr movsd test mul xor neg
* All register references will be 32-bit references.

  `./disasm.py <path-to-binary-file>`

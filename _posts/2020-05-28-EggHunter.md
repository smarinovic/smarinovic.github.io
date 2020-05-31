---
title: Egg Hunter
author: Stipe Marinovic
date: 2020-05-28 23:00:00 +0800
categories: [Blogging, Tutorial]
tags: [slae, shellcoding]
toc: true
---

** PAGE STILL UNDER CONSTRUCTION **

## Introduction ##

Egg Hunter is piece of code used to search for an "egg" in memory.  
Egg as such is just a 4 bytes string, usually: "w00t" (or something unique) which is added twice as prefix to a shellcode and thus marks beggining of shell code.  
Egg Hunter is useful in situation when buffer overflow vulnerability provides limited space, not large enough for placing shell code, but still shell code ends up somehow, somewhere in a memory. For example, HTTP header can be vulnerable to buffer overflow and shell code can can be delivered as payload within POST request.   
So instead of direct execution of shellcode, Egg Hunter searches for a egg in a memory and once it founds egg (two instances of egg) it passes execution to a shellcode located after the egg.  
Egg is appended twice as prefix to shell code in order to prevent Egg Hunter to find itself, meaning that egg is "w00t" but Egg Hunter is looking for two occurences of egg (w00t) in a row (w00tw00t). 

## Prototype ##

We could write Egg Hunter in pseudo code as follows:
```
x = 0 # starting memory location

While(True):
  if read(4 bytes at x) == "w00t":           # read 4 bytes and compare to egg (w00t)
    if read(4 bytes at x+4) == "w00t":       # if first 4 bytes are eaqual to egg, read next 4 bytes
      execute x+8                            # if another occurance of egg is found, pass execution to x+8 (shell code location)
  x = x+1                                    # if egg isn't found, increase memory location +1
```

## First attempt ##

Let's write an Egg Hunter in assembly code based on prototype and see what will happen.

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
When we compile it, link it, and run it, we get an segmentation fault when comparing egg with address in EAX.

```
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x0 
EDX: 0x1 
ESI: 0x0 
EDI: 0x0 
EBP: 0x0 
ESP: 0xbffff360 --> 0x1 
EIP: 0x8049003 (<NEXT_ADDRESS+1>:       cmp    DWORD PTR [edx],0x74303077)
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048ffe:   add    BYTE PTR [eax],al
   0x8049000 <_start>:  xor    edx,edx
   0x8049002 <NEXT_ADDRESS>:    inc    edx
=> 0x8049003 <NEXT_ADDRESS+1>:  cmp    DWORD PTR [edx],0x74303077
   0x8049009 <NEXT_ADDRESS+7>:  jne    0x8049002 <NEXT_ADDRESS>
   0x804900b <NEXT_ADDRESS+9>:  cmp    DWORD PTR [edx+0x4],0x74303077
   0x8049012 <NEXT_ADDRESS+16>: jne    0x8049002 <NEXT_ADDRESS>
   0x8049014 <NEXT_ADDRESS+18>: add    edx,0x8
[------------------------------------stack-------------------------------------]
0000| 0xbffff360 --> 0x1 
```
The reason we got segmentation fault is because program is trying to read unallocated memory.  
To mitigate this issue, there are few possible solutions. Solution we will implement is based on ACCESS syscall.

....

## The access syscall ##

From the `man 2 access` pages we can see that access syscall takes two arguments and checks if calling process can access file pathname. At first it seams non usefull to us, but the thing is, access can also accept memory address instead of file pathname and as such can verify if user can access memory location.  

```
int access(const char *pathname, int mode);
```

> access() checks whether the calling process can access the file pathname. If pathname is a symbolic link, it is dereferenced.
> access() and faccessat() may fail if: EFAULT pathname points outside your accessible address space.

So to succesfully use access, we need to monitor EFAULT.

EFAULT is defined in `/usr/include/libr/sflib/common/sftypes.h` file and F_OK is defined in `/usr/include/unistd.h` file.
 that has code 14, or 0xf2 in negative form.

#define EFAULT          14      /* Bad address */

.... stil under construction ....

## References ##

* [Corlean - exploit writing tutorial](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
* [Art from code blog](https://artfromcode.wordpress.com/2018/03/23/slae-assignment-3-the-egg-hunter/)
* [IllegalBytes blog](https://illegalbytes.com/2018-03-20/slae-assignment-3-linux-x86-egghunting/)
* [Coffeegist blog](https://coffeegist.com/security/slae-exam-3-egg-hunter-shellcode/)
* [Ryuke Ackerman's blog](https://medium.com/@ryukeackerman/securitytube-linux-assembly-expert-slae-assignment-writeups-x03-egg-hunter-shellcode-ea53bf7a12eb)

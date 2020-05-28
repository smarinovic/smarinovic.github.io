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
Egg is just a two series of 4 bytes string, usually: "w00t" (w00tw00t) which is added as prefix to a shellcode and thus marks beggining of shell code.
Egg Hunter is useful in situation when buffer overflow vulnerability provides limited space, not large enough for placing shell code, but still shell code ends up somewhere in a memory. 
So instead of executing shellcode, egghunter searches for a egg in a memory and once it founds egg it passes execution to a shellcode located after the egg.
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

## First try ##

Let's write an Egg Hunter in assembly code based on prototype and see what will happen.

```
global _start

_start:

XOR EAX, EAX                    ; clear EAX

NEXT_ADDRESS:                   ; label used for looping
  INC EAX                       ; increase EAX by 1

  CMP dword [eax], 0x74303077   ; Compare 4 bytes with w00t
  JNZ SHORT NEXT_ADDRESS        ; if w00t not found, jump to NEXT_ADDRESS

  CMP dword [edx+4], 0x74303077 ; if w00t found, compare next 4 bytes with w00t 
  JNZ SHORT NEXT_ADDRESS        ; if second w00t not found, jump to NEXT_ADDRESS

  ADD EAX, 0x8                  ; if two eggs are found, increase EAX + 8         
  JMP EAX                       ; jump to EAX + 8 address where shell code would be located

``` 
But when we try to run it and observe behaviour with GDB we get an segmentation fault.

```
Program received signal SIGSEGV, Segmentation fault.                                                                                                                  
[----------------------------------registers-----------------------------------]                                                                                      
EAX: 0x1                                                                                                                                                              EBX: 0x0                                                                                                                                                              ECX: 0x0                                                                                                                                                              EDX: 0x0                                                                                                                                                              ESI: 0x0                                                                                                                                                              EDI: 0x0                                                                                                                                                              EBP: 0x0                                                                                                                                                              ESP: 0xbffff360 --> 0x1                                                                                                                                               EIP: 0x8049003 (<NEXT_ADDRESS+1>:       cmp    DWORD PTR [eax],0x74303077)                                                                                            EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)                                                                                     [-------------------------------------code-------------------------------------]                                                                                         0x8048ffe:   add    BYTE PTR [eax],al                                                                                                                                 0x8049000 <_start>:  xor    eax,eax
   0x8049002 <NEXT_ADDRESS>:    inc    eax
=> 0x8049003 <NEXT_ADDRESS+1>:  cmp    DWORD PTR [eax],0x74303077
   0x8049009 <NEXT_ADDRESS+7>:  jne    0x8049002 <NEXT_ADDRESS>
   0x804900b <NEXT_ADDRESS+9>:  cmp    DWORD PTR [edx+0x4],0x74303077
   0x8049012 <NEXT_ADDRESS+16>: jne    0x8049002 <NEXT_ADDRESS>
   0x8049014 <NEXT_ADDRESS+18>: add    eax,0x8
[------------------------------------stack-------------------------------------]
0000| 0xbffff360 --> 0x1 
0004| 0xbffff364 --> 0xbffff4ed ("/root/repository/slae-exam/assignment03/egghunter1")
0008| 0xbffff368 --> 0x0 
```
The reason we got segmentation fault is because program is trying to read unallocated memory.  
To mitigate this issue, there are two possible solutions, both are relying on following syscalls:
- SYS_SIGACTION
- SYS_ACCESS

....

## References ##

* [Corlean - exploit writing tutorial](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
* [Art from code blog](https://artfromcode.wordpress.com/2018/03/23/slae-assignment-3-the-egg-hunter/)
* [IllegalBytes blog](https://illegalbytes.com/2018-03-20/slae-assignment-3-linux-x86-egghunting/)
* [Coffeegist blog](https://coffeegist.com/security/slae-exam-3-egg-hunter-shellcode/)
* [Ryuke Ackerman's blog](https://medium.com/@ryukeackerman/securitytube-linux-assembly-expert-slae-assignment-writeups-x03-egg-hunter-shellcode-ea53bf7a12eb)

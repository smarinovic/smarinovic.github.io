---
title: Basic buffer overflow
author: Stipe Marinovic
date: 2020-04-30 00:34:00 +0800
categories: [Blogging, Tutorial]
tags: [pentest, ctp, bof]
toc: true
---

```
#!/usr/bin/python
import sys
from boofuzz import *

host = '192.168.0.31'      # Server's IP address
port = 9999                # Port on which application is listening
temp = " "                 # Global varialbe to store last sent payload.

# Function receive_banner is used to receive data from socket and detect crash when no resposne is detected
def receive_banner(target, fuzz_data_logger, session, sock):
   global temp 
   data=sock.recv(20000)   # Try to recieve data from socket and if banner is not detected report crash
   if not "Welcome to Vulnerable Server! Enter HELP for help." in data:
      print "\n######################################################\n"
      print "[+] No banner received - application may be crashed"
      print "[+] Payload length: " + str (len(temp))
      print "[+] Payload saved in crash_report.txt"
      print "[+] Fuzzing ended"
      print "\n######################################################\n"
      f = open("crash_report.txt", "w")
      f.write(temp)  # Write payload from temp global variable. Session.last_send containes next sent payload and not the one that crashed the application.
      f.close()
      sys.exit(-1)
   else:
      temp=session.last_send  # If banner is receviced from socket - store last sent payload into temp variable  

def main():

   session = Session(post_test_case_callbacks=[receive_banner], target = Target(connection = SocketConnection(host, port, proto='tcp')))

   s_initialize("TRUN command")
   s_string("TRUN", fuzzable = True)
   s_delim(" ", fuzzable = True)
   s_string("TEST", fuzzable = True)

   session.connect(s_get("TRUN command"))
   session.fuzz()

if __name__ == "__main__":
    main()
 
```

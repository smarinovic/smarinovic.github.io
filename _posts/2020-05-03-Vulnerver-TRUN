
'''
#!/usr/bin/python
import sys
from boofuzz import *

host = '192.168.0.31'
port = 9999
temp = " "

def receive_banner(target, fuzz_data_logger, session, sock):
   global temp
   data=sock.recv(20000)
   if not "Welcome to Vulnerable Server! Enter HELP for help." in data:
      print "\n######################################################\n"
      print "[+] No banner received - application may be crashed"
      print "[+] Payload length: " + str (len(temp))
      print "[+] Payload saved in crash_report.txt"
      print "[+] Fuzzing ended"
      print "\n######################################################\n"
      f = open("crash_report.txt", "w")
      f.write(temp)
      f.close()
      sys.exit(-1)
   else:
      temp=session.last_send

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
 '''
 

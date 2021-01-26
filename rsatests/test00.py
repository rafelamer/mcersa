#!/usr/bin/python3
# -*- utf-8 -*-
#
try:
    from cypari import pari
except:
    print ("""To run this program, you have to install the python
library cypari with the command
~# pip3 install cypari
""")

pari.allocatemem(16*1024*1024)
f = open("primes.txt","r")

for line in f:
    line = line.replace("\n",'')
    line.strip()
    try:
        p = pari(int(line))
    except:
        pass
    if not p.isprime():
        print (p)
        print ("is not prime!!!!!!")
    else:
    	print ("The number is prime")

f.close()

#!/usr/bin/python
# -*- utf-8 -*-
#
try:
    from cypari import pari
except:
    print """To run this program, you have to install the python 
library cypari with the command
~# pip install cypari
"""
    
f = open("primes.txt","r")

for line in f.xreadlines():
    line = line.replace("\n",'')
    line.strip()
    try:
        p = pari(int(line))
    except:
        pass
    if not p.isprime():
        print p
        print "is not prime!!!!!!"
    else:
    	print "The number is prime"

f.close()    

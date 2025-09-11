#!/usr/bin/python 
import numpy, sys
import binascii

if __name__ == '__main__': 
    try: 
        string = sys.argv[1] 
    except IndexError: 
        print("Usage: %s INPUTSTRING" % sys.argv[0]) 
        sys.exit() 

    byte_list = []
    for i in range(0, len(string), 4):
        byte_list.append(string[i:i+4][::-1])

    byte_list.reverse()

    for b in byte_list:
        x = binascii.hexlify(bytes(b,encoding='utf8'))
        print("\"   push " + "0x"+x.decode("utf-8") + "                 ;\" #" + b)

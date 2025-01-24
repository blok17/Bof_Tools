import sys, pandas
from colorama import Fore
import argparse 

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="Input file to analyze")
parser.add_argument("-b", "--bads", help="Bad characters already found in the form of '00,0a,6b")
parser.add_argument("-e", "--example", help="Print example file format accepted", action="store_true")

print("  _______           __      ___          __               ")
print(" / ___/ /  ___ ____/ /__   / _ )___ ____/ /__   ___  __ __")
print("/ /__/ _ \\/ -_) __/  '_/  / _  / _ `/ _  (_-<_ / _ \\/ // /")
print("\\___/_//_/\\__/\\__/_/\\_\\__/____/\\_,_/\\_,_/___(_) .__/\\_, / ")
print("                     /___/                   /_/   /___/  ")
print("                                         by 0x5c4r3\n")

args = parser.parse_args()

o_array = ["01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f","10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f","20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f","30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f","40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f","80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f","90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f","a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af","b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf","c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf","d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df","e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef","f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"]

if(args.example): 
    print("0:000> db esp L100\n"
    "00a5a360  01 02 03 04 05 06 07 08-09 0a 0b 0c 0d 0e 0f 10  ................\n"
    "00a5a370  11 12 13 14 15 16 17 18-19 1a 1b 1c 1d 1e 1f 20  ............... \n"
    "00a5a380  21 22 23 24 25 26 27 28-29 2a 2b 2c 2d 2e 2f 30  !\"#$%&'()*+,-./0\n"
    "00a5a390  31 32 33 34 35 36 37 38-39 3a 3b 3c 3d 3e 3f 40  123456789:;<=>?@\n"
    "00a5a3a0  41 42 43 44 45 46 47 48-49 4a 4b 4c 4d 4e 4f 50  ABCDEFGHIJKLMNOP\n"
    "00a5a3b0  51 52 53 54 55 56 57 58-59 5a 5b 5c 5d 5e 5f 60  QRSTUVWXYZ[\\]^_`\n"
    "00a5a3c0  61 62 63 64 65 66 67 68-69 6a 6b 6c 6d 6e 6f 70  abcdefghijklmnop\n"
    "00a5a3d0  71 72 73 74 75 76 77 78-79 7a 7b 7c 7d 7e 7f 80  qrstuvwxyz{|}~..\n"
    "00a5a3e0  81 82 83 84 85 86 87 88-89 8a 8b 8c 8d 8e 8f 90  ................\n"
    "00a5a3f0  91 92 93 94 95 96 97 98-99 9a 9b 9c 9d 9e 9f a0  ................\n"
    "00a5a400  a1 a2 a3 a4 a5 a6 a7 a8-a9 aa ab ac ad ae af b0  ................\n"
    "00a5a410  b1 b2 b3 b4 b5 b6 b7 b8-b9 ba bb bc bd be bf c0  ................\n"
    "00a5a420  c1 c2 c3 c4 c5 c6 c7 c8-c9 ca cb cc cd ce cf d0  ................\n"
    "00a5a430  d1 d2 d3 d4 d5 d6 d7 d8-d9 da db dc dd de df e0  ................\n"
    "00a5a440  e1 e2 e3 e4 e5 e6 e7 e8-e9 ea eb ec ed ee ef f0  ................\n"
    "00a5a450  f1 f2 f3 f4 f5 f6 f7 f8-f9 fa fb fc fd fe ff 43  ...............C\n")
    sys.exit()

bad_chars = []

if(args.bads):
    bad_chars = args.bads.split(",")

try:
    f = open(args.file, "r")
    data = f.read()
    i_array = data.split(' ')
except:
    print("usage: check_bads.py [-h] [-f FILE] [-b BADS] [-e]")
    sys.exit()

pre = []
post = []
i_word = []
check = 0
for word in i_array:
    position = i_array.index(word)
    if len(word) == 2 and check == 0:
        pre.append(word)
    if len(word) == 5:
        check = 1
        part = word.split('-')
        pre.append(part[0])
        pre.append(part[1])
    if len(word) == 2 and check == 1:
        post.append(word)
    if len(word) > 8:
        for p in pre:
            i_word.append(p)
        for p in post:
            i_word.append(p)
        check = 0
        pre = []
        post = []

counter = 0
overflow = 0

final = []
reds = []
for o_word in o_array:
    
    #Check for eof
    if counter > len(o_array)-1:
        print(Fore.GREEN + "No char missing.")
        sys.exit()
    
    #Check for only interesting words
    while(len(i_word[counter]) != 2 and len(i_word[counter]) != 5):
        counter = counter + 1
    
    #Already Found BadChar Detected, Skip Iteration
    if(o_word in bad_chars):
        overflow = 0
        continue

    #New BadChar Detected
    elif(i_word[counter] not in bad_chars and i_word[counter] != o_word):
        #print(Fore.RED + "Missing Char:", o_word)
        reds.append(o_word)
        final.append(o_word)
        overflow = overflow +1
        
        if(overflow == 4):
            last_index = o_array.index(o_word)
            print(Fore.RED + "[+] More than 4 chars misplaced, correct and re-iterate.")
            c = 0
            print(Fore.BLUE + "###############################################")
            for i in final:
                if c == 16:
                    print("\n",end='')
                if(i in reds):
                    print(Fore.RED + i + " ",end='')
                    c = c+1
                else:
                    print(Fore.WHITE + i + " ",end='')
                    c = c+1
            print(Fore.BLUE + "\n###############################################")
            sys.exit()


    #If all good, keep going
    elif(i_word[counter] == o_word):
        overflow = 0
        counter = counter+1
        final.append(o_word)
        continue

f.close()

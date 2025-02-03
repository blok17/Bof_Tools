import sys
import struct
import argparse
from colorama import Fore
import os.path
import subprocess
from textwrap import wrap
import re
from pathlib import Path

print(Fore.MAGENTA + "    _____           __                     __           __                    ")
print(Fore.MAGENTA + "   / __(_)___  ____/ /    ____ _____ _____/ /___ ____  / /______  ____  __  __")
print(Fore.MAGENTA + "  / /_/ / __ \\/ __  /    / __ `/ __ `/ __  / __ `/ _ \\/ __/ ___/ / __ \\/ / / /")
print(Fore.MAGENTA + " / __/ / / / / /_/ /    / /_/ / /_/ / /_/ / /_/ /  __/ /_(__  ) / /_/ / /_/ / ")
print(Fore.MAGENTA + "/_/ /_/_/ /_/\\__,_/_____\\__, /\\__,_/\\__,_/\\__, /\\___/\\__/____(_) .___/\\__, /  ")
print(Fore.MAGENTA + "                 /_____/____/            /____/               /_/    /____/   ")
print(Fore.MAGENTA + "                                                     by 0x5c4r3")
print(Fore.WHITE + "")

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--files", help="Comma separated list of input files to get gadgets from (i.e. /opt/lib1.dll,/opt/lib2.dll)")
parser.add_argument("-b", "--bads", help="Comma separated list of bad characters (i.e. 00,0a,ba)")
parser.add_argument("-B", "--base", help="Use default image offset", default=False)#, action=argparse.BooleanOptionalAction)
parser.add_argument("-o", "--output", help="Output file. If not set, output to stdout")
parser.add_argument("-c", "--clean", help="Print out the cleanest gadgets (avoid gadgets with ops like 'call,'jmp'...)", action='store_true')
parser.add_argument("-s", "--search", help="Regex search through gadgets (to be used with -f)")
parser.add_argument("-rn", "--result_number", help="Max number of search result in output (to be used with -s)", default=10)
parser.add_argument("-F", "--formatted", help="Format search output lines to be like 'payload += struct.pack(\"<L\",0x12345678)' # pop esp # xchg eax,ebx # ret # [file.dll]", action='store_true')


args = parser.parse_args()

#######################################################
################### FUNCTIONS #########################
#######################################################

############# SEARCH ##################################

def find_gadget_with_regex(file, regex, max_results, formatted):
    regex = re.compile(regex)
    matching_lines = []
    
    with open(file, 'r') as file:
        lines = [line.rstrip() for line in file]
        for gadget in lines:
            # search with regex # and exclude filters
            if regex.search(gadget): #and not any(f in gadget for f in filter):
                if(formatted):
                    gadget_formatted = "payload += struct.pack(\"<L\"," + gadget.split(':')[0] + ") #" + gadget.split(':')[1]
                    matching_lines.append(gadget_formatted)
                else:    
                    matching_lines.append(gadget)
                
                if len(matching_lines) >= int(max_results):
                    break
    return matching_lines


################ GET GADGETS #######################

def dump_gadgets(file_path, args):
    if "linux" in sys.platform:
        executable = './rp-lin'
    elif "win32" in sys.platform:
        executable = 'rp++.exe'
    else:
        print(Fore.RED, "We can't run this script in", sys.platform)
        exit(1)
    if not args.base:
        cmd = f'{executable} -r 5 -f {file_path}'
        print(" Running: ",end='')
        print(Fore.GREEN, cmd)
    else:
        cmd = f'{executable} --va 0x0 -r 5 -f {file_path}'
        print(" Running: ",end='')
        print(Fore.GREEN,cmd)
    output = subprocess.run(cmd, shell=True, capture_output=True)
    if output.stderr:
        print("Error with rp++")
        #print(Fore.RED, f"{ERR} stderr on rp++")
        #print(Fore.RED, f"{ERR} {output.stderr.decode()}")
    output_lines = output.stdout.decode().split('\n')
    
    data = []
    for i in output_lines:
        
        if "ret" not in i:
            continue

############ CHECK BAD CHARACTERS #####################
        if(args.bads):
            part = i
            address = part.split(' ')[0]
            address = address.replace(':','')
            couples = [address[part:part+2] for part in range(0, len(address), 2)]
            bad_chars = args.bads.split(',')
            if(any(x in couples for x in bad_chars)):
                continue
        
        line = "#".join(i.split(';')[:-1])
        filename = str(file_path.split('/')[-1:])
        line += "# " + filename

############ CHECK BAD OPERATIONS ##################### 
        if(args.clean == 1):
            bad_ops = ['clts','hlt','outsd','outsb','lmsw','ltr','lgdt','lidt','lldt','mov cr','mov dr','mov tr','in','ins','invlpg','invd','out','outs','cli','cli','sti','popf','pushf','int','iret','iretd','swapgs','wbinvd','call','jmp','leave','ja','jb','jc','je','jr','jg','jl','jn','jo','jp','js','jz','lock','enter','enter','wait','???']
            
            ops_array = line.split(' ; \\x')[0].split(': ')[1].split(' # [')[0].split(' # ') 
            ops_address = line.split(':')[0]
             
            is_bad = 0

            for i in ops_array:
                for j in bad_ops:
                    if(j in i.split(' ')[0]):
                        is_bad = 1
            if(is_bad == 1):
                is_bad = 0
                continue
            else:
                is_bad = 0

        data.append(line)
    return data

#################### MAIN #############################
#try:
if(args.search is None and args.files is None):
    parser.print_help(sys.stderr)
    exit()

if(args.search is not None):
    result = []
    for line in find_gadget_with_regex(args.files, args.search, max_results=args.result_number, formatted=args.formatted):
        result.append(line)    
   
    if(args.formatted):
        for i in result:
            print(i)
        print(Fore.GREEN, "\n[+] Formatted Output.")
        exit()

    if len(result) == 0:
        print(Fore.RED, "[+] No results found based on your search.")
        exit() 
    for i in result:
        print(Fore.GREEN,i.split(' ')[0].split(':')[0],end='')
        print(Fore.WHITE,i.split(':')[1].split(' # [')[0],end='')
        print(Fore.BLUE,'[ '+ i.split(' # [\'')[1].split('\']')[0] + ' ]') 
    
    if(args.result_number != 10):
        print(Fore.WHITE, '\n [+]',end='')
        print(Fore.WHITE, len(result),end='')
        print(Fore.WHITE, "gadgets found (Default)")
        print(Fore.GREEN, "Max Number of result specified:", str(args.result_number))
    else:
        print(Fore.WHITE, '\n [+]',end='')
        print(Fore.WHITE, len(result),end='')
        print(Fore.WHITE, "gadgets found (Default)")
        print(Fore.YELLOW, "If not enough, specify the max number of results with -rn")
    exit()

clean_messed_gadgets = []
if(args.files is not None):
    
    #check if file exists
    for file in args.files.split(","): 
        file_path = file
        path = Path(file_path)
        if path.is_file():
            clean_messed_gadgets.extend(dump_gadgets(file_path, args))
        else:
            print(Fore.RED,"File not found:", file_path)
            exit()

    clean_sorted_gadgets = sorted(clean_messed_gadgets, key=len)

    print(Fore.GREEN, '[+]',end='')
    print(Fore.GREEN, len(clean_sorted_gadgets), "gadgets found.")
    extensions = ['exe','dll']
    if(len(clean_sorted_gadgets) == 0 and file_path.split('.')[1] not in extensions):
        print(Fore.YELLOW, "[-] Extension not recognized:", file_path.split('.')[1])
        print(Fore.YELLOW, 'Maybe wrong file? ->',end='')
        print(Fore.WHITE,file)

    if(args.output):
        output_file = args.output
        f = open(output_file, "w")
        for i in clean_sorted_gadgets:
            i += "\n"
            f.write(i)
        f.close()
        print(Fore.WHITE," [+] Gadgets saved to file: ",end='')
        print(Fore.GREEN, args.output)

    else:
        for i in clean_sorted_gadgets:
            print(Fore.WHITE,i)

#except:
#    print("Please Submit File.")
#    exit()






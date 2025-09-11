<img src='https://raw.githubusercontent.com/blok17/Bof_Tools/refs/heads/main/bofTools.png' width="200">

Bunch of interesting tools to automatize x86 BoF Exploitation.

#### Configuration:
##### Automatic
Open a smb share on Bof_tools and access it from the Windows Remote machine.
Run config.ps1.

##### Manual
In C:\Program Files\Windows Kits\10\Debuggers\x86:
- windbglib.py
- windbglib.pyc
- mona.py

In C:\Program Files\Windows Kits\10\Debuggers\x86\winext:
- pykd2.pyd
- pykd3.dll
- narly.dll

---
### Check_Bads.py

Quick and simple tool to check for any missing chars when controlling Bad Characters during Buffer Overflow Exploitation.
It will find all the badchars and stop once 4 consecutive badchars are found.
It requires a `db esp L100`, aligned so that it starts with `01`. An example named 'badchar_example.txt' is provided in the repository.
```
  _______           __      ___          __               
 / ___/ /  ___ ____/ /__   / _ )___ ____/ /__   ___  __ __
/ /__/ _ \/ -_) __/  '_/  / _  / _ `/ _  (_-<_ / _ \/ // /
\___/_//_/\__/\__/_/\_\__/____/\_,_/\_,_/___(_) .__/\_, / 
                     /___/                   /_/   /___/  
                                         by 0x5c4r3


usage: check_bads.py [-h] [-f FILE] [-b BADS] [-e]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Input file to analyze
  -b BADS, --bads BADS  Bad characters already found in the form of '00,0a,6b'
  -e, --example         Print example file format accepted

```
---

### find_gadgets.py

Quick and simple tool to dump/search gadgets based on one or more files.
```
    _____           __                     __           __                    
   / __(_)___  ____/ /    ____ _____ _____/ /___ ____  / /______  ____  __  __
  / /_/ / __ \/ __  /    / __ `/ __ `/ __  / __ `/ _ \/ __/ ___/ / __ \/ / / /
 / __/ / / / / /_/ /    / /_/ / /_/ / /_/ / /_/ /  __/ /_(__  ) / /_/ / /_/ / 
/_/ /_/_/ /_/\__,_/_____\__, /\__,_/\__,_/\__, /\___/\__/____(_) .___/\__, /  
                 /_____/____/            /____/               /_/    /____/   
                                                     by 0x5c4r3

usage: find_gadgets.py [-h] [-f FILES] [-b BADS] [-o OUTPUT] [-s SEARCH] [-ns NSEARCH] [-c] [-rn RESULT_NUMBER] [-F FORMATTED] [--base BASE]                                                                     
options:                                                                                                                                                                                  
  -h, --help            show this help message and exit                                                                                                                                   
  -f, --files FILES     Comma separated list of input files to get gadgets from (i.e. /opt/lib1.dll,/opt/lib2.dll). If used with -s, input file to search from (i.e. /opt/lib1_gadgets.txt).                  
  -b, --bads BADS       Comma separated list of bad characters (i.e. 00,0a,ba)                                                                                                            
  -o, --output OUTPUT   Output file. If not set, output to stdout                                                                                                                         
  -s, --search SEARCH   Regex search through gadgets (to be used with -f)                                                                                                                 
  -ns, --nsearch NSEARCH                                                                                                                                                                  
                        Negative regex search through gadgets (to be used with -f)                                                                                                        
  -c, --clean           Print out the cleanest gadgets (avoid gadgets with ops like 'call,'jmp'...)                                                                                       
  -rn, --result_number RESULT_NUMBER                                                                                                                                                      
                        Max number of search result in output (to be used with -s)                                                                                                        
  -F, --formatted FORMATTED                                                                                                                                                               
                        Format output for search function, choosing between:                                                                                                              
                        - packed: "payload += struct.pack("<L",0x12345678)"                                                                                                               
                        - offset: "payload += struct.pack("<L", dll_base + 0x123)", to be used with dynamically fetched dll base address to bypass ASLR                                   
  --base BASE           Use custom specified BaseAddress (for ASLR Bypassing) 
```

All the other tools are taken from the below listed references:<\br>
https://github.com/epi052/osed-scripts<\br>
https://github.com/nop-tech/code_caver<\br>
https://github.com/epi052/osed-scripts<\br>
https://github.com/0vercl0k/rp<\br>

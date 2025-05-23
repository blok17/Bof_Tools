# Bof Tools
<img src='https://sdmntprukwest.oaiusercontent.com/files/00000000-5108-6243-b336-91c8df3cdf5e/raw?se=2025-05-23T09%3A50%3A41Z&sp=r&sv=2024-08-04&sr=b&scid=95fc07b6-68b4-50f8-9dee-d4875aadac8c&skoid=82a3371f-2f6c-4f81-8a78-2701b362559b&sktid=a48cca56-e6da-484e-a814-9c849652bcb3&skt=2025-05-23T07%3A24%3A25Z&ske=2025-05-24T07%3A24%3A25Z&sks=b&skv=2024-08-04&sig=qpTCaMnlVzD%2BVzNcqgEHYZp55rIRigabDOc0EoGs4Xg%3D'>

Bunch of interesting tools to automatize x86/64 BoF Exploitation.

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
It requires a `db esp L100` with the output aligned to start with `01`.
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
### egghunter.py

Quick and simple tool to create egghunters based on user configuration.
```
                    __                __                       
  ___  ____ _____ _/ /_  __  ______  / /____  _________  __  __
 / _ \/ __ `/ __ `/ __ \/ / / / __ \/ __/ _ \/ ___/ __ \/ / / /
/  __/ /_/ / /_/ / / / / /_/ / / / / /_/  __/ /  / /_/ / /_/ / 
\___/\__, /\__, /_/ /_/\__,_/_/ /_/\__/\___/_(_)/ .___/\__, /  
    /____//____/                               /_/    /____/   
                                             by 0x5c4r3        


usage: egghunter.py [-h] [-t TAG] [-b BAD_CHARS [BAD_CHARS ...]] [-s] [-o]

options:
  -h, --help            show this help message and exit
  -t TAG, --tag TAG     tag for which the egghunter will search (default: c0d3)
  -b BAD_CHARS [BAD_CHARS ...], --bad-chars BAD_CHARS [BAD_CHARS ...]
                        space separated list of bad chars to check for in final egghunter without ' nor " (default: 00)
  -s, --seh             create an seh based egghunter instead of NtAccessCheckAndAuditAlarm
  -o, --output          save the egghunter into a egghunter.bin file to then encode it
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

usage: find_gadgets.py [-h] [-f FILES] [-b BADS] [-B BASE] [-o OUTPUT] [-c] [-s SEARCH] [-rn RESULT_NUMBER] [-F]

options:
  -h, --help            show this help message and exit
  -f FILES, --files FILES
                        Comma separated list of input files to get gadgets from (i.e. /opt/lib1.dll,/opt/lib2.dll). If used with -s, input file to search from (i.e. /opt/lib1_gadgets.txt).
  -b BADS, --bads BADS  Comma separated list of bad characters (i.e. 00,0a,ba)
  -B BASE, --base BASE  Use default image offset
  -o OUTPUT, --output OUTPUT
                        Output file. If not set, output to stdout
  -c, --clean           Print out the cleanest gadgets (avoid gadgets with ops like 'call,'jmp'...)
  -s SEARCH, --search SEARCH
                        Regex search through gadgets (to be used with -f)
  -rn RESULT_NUMBER, --result_number RESULT_NUMBER
                        Max number of search result in output (to be used with -s)
  -F, --formatted       Format search output lines to be like 'payload += struct.pack("<L",0x12345678)' # pop esp # xchg eax,ebx # ret # [file.dll]

```

### References
https://github.com/epi052/osed-scripts/tree/main

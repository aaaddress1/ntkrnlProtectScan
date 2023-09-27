# ntkrnlProtectScan
One Click Tool to Scan All the Enabled Protection of current Windows NT Kernel

Usage: 
```powershell
PS C:\Users\Pwn> IEX($(IWR https://raw.githubusercontent.com/aaaddress1/ntkrnlProtectScan/main/ntkrnlProtectScan.ps1).Content)
_   _ _____   _  __                    _
| \ | |_   _| | |/ /___ _ __ _ __   ___| |
|  \| | | |   | ' // _ \ '__| '_ \ / _ \ |
| |\  | | |   | . \  __/ |  | | | |  __/ |
|_| \_| |_|   |_|\_\___|_|  |_| |_|\___|_|
 ____            _            _   ____
|  _ \ _ __ ___ | |_ ___  ___| |_/ ___|  ___ __ _ _ __
| |_) | '__/ _ \| __/ _ \/ __| __\___ \ / __/ _ | '_ \
|  __/| | | (_) | ||  __/ (__| |_ ___) | (_| (_| | | | |
|_|   |_|  \___/ \__\___|\___|\__|____/ \___\__,_|_| |_|
 ~ github.com/aaaddress1/ntkrnlProtectScan
 ~ ntkrnlProtectScan [v1]

Windows Environment Version: 10.0.22621.0
Protection Type                                    Status
---------------                                    ------
Supervisor Mode Execution Prevention (SMEP)        On
Kernel Control Flow Guard (KCFG)                   On
Virtualization-based Security (VBS)                Off
Hypervisor-Protected Code Integrity (HVCI)         Off
Kernel Control-Flow Enforcement Technology (KCET)  Off
Credential Guard                                   Off
System Guard Secure Launch                         Off
SMM Firmware Measuremen                            Off

Attack Chance                                             Status
-------------                                             ------
Kernel Data Manipulation                                  Vulnerable
Clear CR4 to disable SMEP for running shellcode in kernel Secured
Abuse PTEs to Run User-mode Shellcode as Supervisor       Secured
Inject Kernel Data with Shellcode to Bypass KCFG          Vulnerable
Kernel-mode ROP chains                                    Vulnerable
Kernel-mode ROP chains to Clear CR4 and disable SMEP      Vulnerable
```

# ntkrnlProtectScan
One Click Tool to Scan All the Enabled Protection of current Windows NT Kernel

Usage: 
```powershell
PS C:\Users\Pwn> IEX($(IWR https://raw.githubusercontent.com/aaaddress1/ntkrnlProtectScan/main/ntkrnlProtectScan.ps1).Content)
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

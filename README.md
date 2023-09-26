# ntkrnlProtectScan
One Click Tool to Scan All the Enabled Protection of current Windows NT Kernel

Usage: 
```powershell
PS:\> IEX $(IWR https://raw.githubusercontent.com/aaaddress1/ntkrnlProtectScan/main/ntkrnlProtectScan.ps1).Content
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
```

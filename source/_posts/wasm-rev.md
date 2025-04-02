---
title: Barbhack 2024 - wasm
date: 2025-04-02
tags: 
- ghidra
- bruteforce
- wasm
category: 
- pwn
---

# Découverte 

file
```
wasm.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)
```

<br>

Le challenge repose sur un système d'authentification intégré dans un fichier WASM. Pour obtenir le flag, il nous faut trouver un moyen de nous connecter en tant qu'administrateur via ce binaire.

<br>

# Décompilation

En cherchant sur internet, je suis tombé sur ce plugin pour ghidra : <a href="https://github.com/nneonneo/ghidra-wasm-plugin">nneonneo/ghidra-wasm-plugin</a>

J'ouvre donc Ghidra, load le plugin et commence à regarder l'environnement.

En examinant les fonctions, j'en identifie deux qui sont particulièrement intéressantes: ```<auth>``` et ```<welcome>```.


Dans la fonction  ```<auth>``` est assez basique, elle prend un string en entrée, et l'affiche dans le terminal comme compte identifié.
Néanmoins, il y a une condition intéressante ici :  
```c
  if (((((cStack_1f == 'D') && (cStack_17 == 'A')) && (cStack_16 == 'T')) &&
      ((((cStack_1a == '$' && (cStack_1d == '1')) &&
        ((cStack_19 == 't' && ((cStack_14 == 'R' && (cStack_1c == 'N')))))) && (cStack_15 == '0'))))
     && ((((local_20 == 0x34 && (local_18 == 0x52)) && (local_1e == 0x6d)) &&
         ((local_1b == 0x31 && (local_13 == 0)))))) {
    unnamed_function_35(s_You_logged_as_admin_ram_0001006f,0);
    local_44 = unnamed_function_27(s_./flag.txt_ram_0001002d,0x1003b);
```

Il semble y avoir un nom d'utilisateur administrateur qui permet de se connecter en tant que superutilisateur. Si cette condition est satifaite, le flag est à nous !

En reprenant tous les caractères, on obtient : "R0TARt$1N1mD4". En inversant cette chaîne: "4Dm1N1$tRAT0R".

A partir de là, cela semble être gagné, mais il reste encore une subtilité.
Le nom d'utilisateur se trouve à un offset X dans le buffer, et nous n'avons pas connaissance de cet offset.

# Bruteforce
N'ayant pas énormément de temps, pour faire plus simple, j'ai décidé de bruteforce l'offset. Voici le code : 
```py
from pwn import *


for i in range(256):
    username = b"a"*i+ b"4Dm1N1$tRAT0R" # aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4Dm1N1$tRAT0R
    
    t = remote("wasm.brb", 3000)

    print(t.recvline().decode())

    t.sendline(username)

    print(t.recvline().decode())
t.interactive()
```

Après 32 essais, l'accès en tant qu'administrateur est obtenu et le flag est récupéré.
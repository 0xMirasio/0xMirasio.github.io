---
layout: post
title: NBCTF 2023 - Itchy Scratchy
subtitle: du reverse exotique
tags: [reverse, z3, scratch]
comments: true
---

### Itchy Scratchy NBCTF 2023

Ce challenge est le 2ème de la catégorie rev du NBCTF 2023. (très bonne surprise ce ctf)

On nous fournit un fichier  **itchyscratchy.sb3**, ces fichiers sont des projets pour scratch 3. 
On peut de manière simple les ouvrir avec Winrar et obtenir les images/son du projets ainsi que le plus important : **projects.json**

projects.json est un fichier qui continent la déclaration de tout les blocks/node/variables du projet.

on peut alors récupérer facilement les valeurs suivantes:

```python
enc = [902, 764, 141, 454, 207, 51, 532, 1013, 496, 181, 562, 342]
alpha = "zvtwrca57n49u2by1jdqo6g0ksxfi8pe1mh3"
```

Il est à noter que j'ai perdu plus d'1heure 30 car j'ai mal recopié le alpha depuis le scratch. Ce qui m'a donné un mauvais flag :)

## Analyse du projet

On peut l'ouvrir sur le site officiel de scratch.

!["Scratch"](/assets/img/posts/nbctf/scratch1.PNG "Scratch project").

Nous avons donc 3 broadcast : good/bad/check
De manière plutot intuitive, il est facile de noter que le "backdrops" qui est une page ou l'on peut mettre d'autre block peut être atteinte via le petit texte backdrops sur la droite.
Ne connaissait absolument pas ceci, j'ai perdu énormement de temps et de frustration à modifier projects.json pour afficher le block "check" qui n'est pas sur la page principale...

## Start

le block principale n'est pas du tout compliqué, en placçant "isaac newton" dans le champ, on obtient à partir d'alpha la liste suivante : 
```python
name = [29, 26, 7, 7, 6, 0, 10, 32, 4, 3, 21, 10]
```

On peut ensuite allez dans backdrops pour voir la fonction check.

## check

!["Scratch"](/assets/img/posts/nbctf/scratch2.PNG "check function").

Ici aussi l'algorithm de vérification du mot de passe n'est pas très compliqué...
Vu que la valeur j est calculé à partir du mot de passe inconnu, le BF va être un peu galère donc je suis vite parti sur une solution sur z3.

ce qui donne : 

```python
from z3 import *

enc = [902, 764, 141, 454, 207, 51, 532, 1013, 496, 181, 562, 342]
name = [29, 26, 7, 7, 6, 0, 10, 32, 4, 3, 21, 10]

alpha = "zvtwrca57n49u2by1jdqo6g0ksxfi8pe1mh3"
s = z3.Solver()

password = [Int(f'password[{i}]') for i in range(12)]

for i in range(12):
    s.add(password[i] >= 0)

tmp = Int('tmp')
j = Int('j')

for i in range(1, 13):
    j = ((i * i) + name[i - 1]) % 12 + 1
    tmp = password[i - 1] * password[j - 1] + (name[i - 1] * name[j - 1])
    s.add(tmp == enc[i - 1])

sat = s.check()
if sat == z3.unsat:
    print("No solution")
else:
    m = s.model()
    print("Model:", m)
    extracted_values = [m.evaluate(password[i]).as_long() for i in range(12)]
    z=  ''.join(alpha[i-1] for i in extracted_values)
    flag = 'nbctf' + '{' + z + '}'
    print(flag)
```

A noter également que pour des raisons magnifiques, scratch qui est un language pour introduire les gens à la programmation utilise l'index 1 comme début dans les tableau. (???). Il faut donc shift d'un élement pour chaque array dans le code. 

On obtient finalement : nbctf{12lett3rf149}

Il est possible également d'utiliser https://leopardjs.com/ pour convertir le projet scratch en JS, ce peut donner une bien meilleure visibilité du code.
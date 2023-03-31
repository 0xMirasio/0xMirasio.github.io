---
layout: post
title: Binaire packé avec un mot de passe
subtitle: Technique générale d'approche pour récuperer la donnée
tags: [reverse, packing]
comments: true
---

## Binaire packé

Il peut arriver de croiser des binaires dont les sections sont chiffré a l'aide d'un mot de passe, qui est demandé au démarrage du programme.  
Il peut-être intéréssant d'étudier des techniques d'approches générale pour retrouver le mot de passse afin de depacker un binaire.

## Approche numéro 1

Nous nous plaçons dans un contexte ou l'on suppose l'algo de chiffrement suffisement fort pour ne pas pouvoir le reverse/bruteforce facilement.
Une approche consiste à guess des plaintexts que l'ont peut retrouver dans le binaire depacker et en déduire des portions du mot de passe, voir tout le mot de passe.  

Parmi les plaintexts on peut avoir : 

- .data => peut être composé en majorité de \x00
- .rodata => un header commun aux binaires peut nous faciliter à trouver un mot de passe.
- .text => pattern ASM de début de code peut-être deviné. (libc_start_main, ...)
- .text => certaines fonctions communes à des binaires peuvent être utiliser pour retrouver le mdp.

En se basant sur ce genre d'information, on peut retrouver en entier ou partiellement le mot de passe. On reproduit l'algo de crypto et on récupère octet par octet le mot de passe initial. 
Si on manque certains octets du mot de passe, ce n'est pas grave car avec un mot de passe partiel on peut récuperer la suite en se basant sur des strings dans .rodata. 

par exemple : 

- mdp : password_is_T???? => .rodata : index X = contact@gnu.o????  
On peut alors deviner que la suite est .org, donc on a 2 caractères supplémentaires. On récupère bout à bout le mot de passe de cette manière.

## Approche numéro 2 

On peut utiliser l'indice de coïncidence.  
l’indice de coincidence est capable de dire si un texte est aléatoire (chiffré, etc) ou un texte humain.
On peut notamment calculer si une zone est aléatoire : 1/256 = 0.003
Pour récuperer le mot de passe on peut alors tester caractère par caractère pour voir qui fait monter le plus l'IC et donc reconstituer progressivement le mot de passe.
Bien sur il faut prévoir plusieurs candidats et instrumenter correctement pour éliminer tout faux positifs.
---
layout: post
title: NBCTF 2023 - flotsam ~ x marks the spot
subtitle: voulez vous une pincée de wasm
tags: [reverse, wasm]
comments: true
---

### NBCTF 2023 - flotsam ~ x marks the spot

On nous fournit une url : **flotsam.chal.nbctf.com**
On se retrouve sur un site avec une sorte de grille contenant plusieurs icones : un bateau, des vagues et des mines.

Une rapide analyse montre que le site tourne avec un module wasm.

## Analyse de l'interface JS

un premier coup d'oeil révele que le site utilise 3 fonctions exportés du module wasm :  add_key, check_x &generate_mines.

En placant quelque breakpoint et le main.js, on repère que add_key est appelé pour chaque touche du clavier pressé, check_x quand l'utilisateur appuie sur la touche 'x' et generate_mines lorsque la page se charge.

!["WASM"](/assets/img/posts/nbctf/wasm1.PNG "wasm key event handler").

les touches 'wasd' vont faire changer la position du bateau, et check_x utilise la position actuelle pour appeler la fonction exporté du wasm. 

Analysons cette fonction

## check_x 

Pour cela, on peut utiliser **WABT** qui permet de jouer avec les fichiers wasm.
On peut télécharger dans les sources du site module.wasm => en réalité c'est un fichier WAT (format texte de wasm). 

Je deteste lire du wasm sous format WAT donc on va utiliser wat2wasm de wabt puuis wasm-decompile pour avoir une version bien plus propre. 

Ce qui donne pour check_x(): 

!["WASM"](/assets/img/posts/nbctf/wasm2.PNG "wasm key event handler").

même sous ce format la, le wasm est très moche à lire. (mais toujours mieux que la version WAT)

Sans trop allez loin dans la fonction, on constate que la position a et b est utilisé pour calculer f = a * 99 + b
Cette valeur est ensuite check avec une valeur stocké à la mémoire 1050280 modulo 9801

le label B_c étant un jump vers la sortie de la fonction, il faut donc trouver un couple de position tel que f soit bon.


!["WASM"](/assets/img/posts/nbctf/wasm3.PNG "check_x test").

(On peut break dans le debugger de chrome tools pour vérifier ce check)

On finit donc par facilement retrouver la bonne position (généré aléatoirement à chaque rechargement de la page)
On obtient donc le flag en appuyant sur x à la bonne position !

!["WASM"](/assets/img/posts/nbctf/wasm4.PNG "flag").


Je n'ai pas eu le temps de terminer le 2ème WASM, basé sur le même site. Il fallait activer une séquence de clé , qui permettait d'activer un "cheatcode" dans add_key(x)


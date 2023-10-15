---
layout: post
title: Writeup Ctf Hexrays madame de Maintenon
subtitle: Quelqu'un à dit goodies?
tags: [reverse, angr]
comments: true
---


# Madame de Maintenon

Ce challenge provient de Hexray.
source du chall : https://hex-rays.com/blog/free-madame-de-maintenon-ctf-challenge/?utm_source=Social-Media-Post&utm_medium=Twitter&utm_campaign=free-madame-de-maintenon-

## Analyse du binaire

Le binaire est un éxecutable Linux 64bit. On peut remarquer l'utilisation de **libSDL2** qui est une lib de rendu d'image.
Le challenge est un crackme dont le mot de passe est prit en argument du programme. 
Après analyse du code on a : 

```
strncpy(password, password_user, 24uLL) <-- le mot de passe fait donc max 24 caractère.
# des index password[24] sont utilisé plus tard donc le mot de passe fait très probablement 24 caractères.
```
Une fois la copie du mot de passe dans le buffer effectué, on commence une série de contrainte sur le mot de passe pour déterminer si il est valide : 
```c
#premier check
if ( *(unsigned __int16 *)&password[16]
       + *(unsigned __int16 *)&password[22]
       - *(unsigned __int16 *)&password[8]
       - *(unsigned __int16 *)&password[14] != 0x1CD4 )
```

Ici, il est important de noter que on a des int16, donc password[16] correspond à 2 octets prit à partir de l'index 16. soit password[16]*256 + password[17] (important pour les solvers z3)

Après quelques check, on remarque qu'une certaine zone de mémoire dans .data est modifié en fonction du mot de passe.
```c
 for ( j = 0LL; j != 0x1D9AD; ++j )
      *(_QWORD *)&memory_zone[8 * j] -= *(_QWORD *)&password[8 * (j - (j / 3  + (((0xAAAAAAAAAAAAAAABLL * (unsigned __int128)j) >> 64) & 0xFFFFFFFFFFFFFFFELL)))];
```

Ici on a des _QWORD* donc 8 octets prit à partir de l'index 8*j
Un peu après, on retrouve d'autre check ansi que des modifications de la zone mémoire memory_zone à différents index.

Pour finir, le programme charge dans une variable une image prit depuis la mémoire memory_zone. 
Si les checks de sécurité ont échoués, alors une autre image est chargé depuis un autre offset de .data
```c
  img_render = SDL_RWFromConstMem(memory_zone, 0xECD6C); #image chargé si tout les check ont réussi
    }
    else
    {
generate_imgfail:
      img_render = SDL_RWFromConstMem(&img_fail, 0x6D1BA); #si fail d'un check, on charge cette image
    }
    img = IMG_LoadTexture_RW(renderer, img_render); #render de l'image
```

Lorsque que l'on éxécute le programme avec le mauvais mot de passe, on retrouve l'image de fail :

!["Fail"](/assets/img/posts/hexrayctf/fail.PNG "image de fail").


Donc nous avons un crackme dont l'image à récupérer dépend du mot de passe d'entrée. 

## Script de résolution 

J'ai d'abord utilisé **z3** pour solve les contraintes une par une mais j'ai du faire une erreur dans mon scripts car je n'obtenais pas de résultats bon.
J'ai décidé d'utiliser **angr** car il répond à mon problème et son setup est très facile.

Pour cela j'ai besoin de 2 adresses : Une adresse qui dit à angr que la solution est OK, et une qui lui dit que c'est un échec.
Pour cela j'ai juste à prendre les adresses de SDL_RwFromConstMem : si on atteint le chargement de l'image packé en mémoire, je considère que le mot de passe est valide car il a passé tout les checks. 

**Attention ne pas oublier de rabaser le programme sur IDA en 0x400000 à cause du PIE pour avoir la même adresse que dans angr**

On a donc : 

```python
addr_fail = 0x4012F7
addr_win = 0x4014EA


import angr
import claripy  

def main():

   
    project = angr.Project("challenge", load_options={'auto_load_libs':False})
    argv = [project.filename]   #argv[0]
    sym_arg_size = 24
    sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)


    argv.append(sym_arg)    #argv[1]
    state = project.factory.entry_state(args=argv)

    sm = project.factory.simulation_manager(state)
    sm = sm.explore(find=addr_win, avoid=addr_fail)

    found = sm.found
    if len(found) > 0:    #   Make sure we found a path before giving the solution
        found = sm.found[0]
        result = found.solver.eval(argv[1], cast_to=bytes)
        print(result)
    else:
        print("nul/20")

main()
```

Après une petite bonne 15minutes d'attente, je trouve enfin le mot de passe : **dR/\x11\x1f\x91t$CM/\x0f\x04\xb9o\r\x16IrV%\xb2p.**
Attendez quoi? 

Erreur classique, mais il y'a plusieurs mot de passes qui passe les checks :). J'atteint donc bien le chargement de la zone mémoire de l'image packé mais l'image résultante n'est pas du tout valide. 

je rajoute donc au script : 
```python
for byte in sym_arg.chop(8):
        state.add_constraints(byte >= 30) 
        state.add_constraints(byte <= 127)
        
#on suppose que HexRay utilise un mot de passe avec des caractères simples.
```

On relance et 15Min plus tard... : **Fr33_M4dam3-De/M4inten0n**
Hop c'est bon !

On obtient donc l'image suivante : 

!["Win"](/assets/img/posts/hexrayctf/win.PNG "image de validation").


Merci à Hexrays pour ce challenge sympatique, j'attend les WU pour avoir un script z3 propre et puis on espère être prit dans les winners des goodies :D.

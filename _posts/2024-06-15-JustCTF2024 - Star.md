---
layout: post
title: JustCTF 2024 - JustTV
subtitle: exotisme
tags: [reverse, mheg]
comments: true
---

### JustCTF 2024 - JustTV

!["Main"](/assets/img/posts/justctf2024/chall.png "Description")


On nous fournit une archive contenant plusieurs fichiers. Notamment des fichiers .asn1 et un fichier `a`

# Analyse des ASN, ou tentative de compréhension de c'est quoi ce chall

!["Main"](/assets/img/posts/justctf2024/files.png "Fichier")

A première vue, on a une série de fichier .ASN qui contiennent des références vers les autres, des charsets et des strings non utiles (météo, mois, ...)

Le fichier a n'est pas un format que je connais, mais je soupsonne d'être la compilation de src, qui pointe vers tv_overlay.asn et un menu (main_menu.asn)

Après quelques temps, je n'ai rien trouvé de concluant. J'ai décoder les .ASN mais je n'ai pas compris comment bien exploiter le fichier. 

Voyant que personne ne solvait après 8H de CTF, les admins ont release un hint sur la compilation : `MHEG`

# MHEG

MHEG (M ultimedia and H ypermedia E xperts G roup)

Le MHEG est un système qui permet de créer des applications utilisées sur le système de télévision , c'est principalement utilisé au Royaume Unis sinon c'est pas très connu.

Bref, après cette indice je télécharge MHEG+Viewer (un jar qui date des années -100 avant JC) + un tool (redbutton, horrible à compiler) pour reconstruire les sources à partir du binaire `a` et les .ASN binaire.

on a donc : 

```
./redbutton/mhegd ../a > ca.mheg
```

=> 

```
{:Application ( '/a' 0 )
        :Items (
                {:Link 1
                        :EventSource 0
                        :EventType IsRunning
                        :LinkEffect (
                                :TransitionTo ( ( '~/tv_overlay.asn' 0 ) )
                        )
                }
        )
        :BackgroundColour '=ff=ff=ff=00'
        :TextCHook 10
        :TextColour '***=00'
        :Font 'rec://font/uk1'
        :FontAttributes 'plain.24.27.0'
}
```

Ok, on a bien les sources des différents fichiers, avec leur lien de logique.
On va pouvoir également utiliser MHEG + Viewer avec les sources pour émuler le code.


!["Main"](/assets/img/posts/justctf2024/mhegviewer.png "mhegviewer")

Ici avec MHEGViewer, on peut simuler le code mheg, placer des breakpoints, voir les variables...
Tout ce qu'il nout faut!

# Analyse du crackme

Dans le menu, on peut choisir Extra => on obtient ce keyboard qwerty avec un mot de passe à rentrer.
On remarque également que le programme utilise principalement du binaire sur 7bits, dans tout ses tests et sa logique.

En suivant la logique du code et en plaçant correctement les breakpoints, on se retrouve avec le pseucode suivant:

```python
charset = "1234567890qwertyuiopasdfghjkl{zxcvbnm_!@#$%^&*+=QWERTYUIOPASDFGHJKL}ZXCVBNM-"
charset_bin = "0000000000000100000100000011000010000001010000110000011100010000001001000101000010110001100000110100011100001111001000000100010010010001001100101000010101001011000101110011000001100100110100011011001110000111010011110001111101000000100001010001001000110100100010010101001100100111010100001010010101010010101101011000101101010111001011110110000011000101100100110011011010001101010110110011011101110000111001011101001110110111100011110101111100111111100000010000011000010100001110001001000101100011010001111001000100100110010101001011"    

assert(len(charset_bin)//7 == len(charset))

# Constante qui est placé dans le programme
base_bin = "11001000010101001000100011001000110010000110100011101010011110110110001001001111001000010110000101110011101011011101011001001011110100011000111100101110000100101001111001111011110111101001110100101100110101111101101110101111001000111100111000000100101001101000001101010111101010010100000101010001010010010100101111011101111100110010101000100000001101000011101001011111101001100110111001000000110110101010111100100101111110111010011110001000011011010010110000000011111100001100"


# Ici notre entrée va être transformé en binaire via le charset set au début. On ne cast pas directement notre byte du mot de passe en bin, mais à partir de l'index du caractère dans le charset (ça revient au même en soit)
pwd_charset = ""
for i in range(len(pwd)):

    index = charset.index(pwd[i])
    i_l = index * 7
    i_h = (index+1)*7
    blob = charset_bin[i_l:i_h]
    pwd_charset += blob

```

Juste après, le programme va shift le blob binaire de base à partir de la taille du mot de passe, on va avoir :

```python
x = SIZE_MDP*7 #7bits
base_bin_x = base_bin[x:] + base_bin[:x] 
```

Le programme va ensuite créer un nouveau blob binaire à partir de notre blob binaire généré via le mot de passe : 

```python
for i in range(len(pwd_charset)):

    v1 = int(pwd_charset[i])
    v2 = int(base_bin_x[i])

    if v1 == v2:
        r = 0
    else:
        r= 1

    new_blob.append(r)

if new_blob == blob_final:
    set_color(OK)
else:
    set_color(FAIL)
```

On a donc tout les éléments pour retrouver le mot de passe: 

- le mot de passe est entre 1 et len(base_bin)//7
- il commence par justCTF{

On va donc tester toutes les tailles de mot de passe pour avoir tout les base_bin_x possible (en fonction des shifts, on aura pas le même résultat)

```python

# l'idée ici est de tester tout les shifts avec le mdp justCTF{AAAA*size_remaining}
# Si une taille de mdp est bonne, les 7 * 7bit premiers tests devraient être bon, sinon on fail et on continue
for size in range(68):
    x = size*7
    base_bin_x = base_bin[x:] + base_bin[:x] 
    for i in range(len(pwd_charset)):

        v1 = int(pwd_charset[i])
        v2 = int(base_bin_x[i])

        if v1 == v2:
            r = 0
        else:
            r= 1

        if r != final[i]:
            break

        if i > 7*7:
            print(f"Shift OK for {x}") # x= 33 OK, le seul
```

X=33 étant l'unique taille valide, on en conclue que le mot de passe fait 33caractères

On peut donc maintenant solve le crackme, avec le bon shift : 
```python
charset = "1234567890qwertyuiopasdfghjkl{zxcvbnm_!@#$%^&*+=QWERTYUIOPASDFGHJKL}ZXCVBNM-"
charset_bin = "0000000000000100000100000011000010000001010000110000011100010000001001000101000010110001100000110100011100001111001000000100010010010001001100101000010101001011000101110011000001100100110100011011001110000111010011110001111101000000100001010001001000110100100010010101001100100111010100001010010101010010101101011000101101010111001011110110000011000101100100110011011010001101010110110011011101110000111001011101001110110111100011110101111100111111100000010000011000010100001110001001000101100011010001111001000100100110010101001011"    

assert(len(charset_bin)//7 == len(charset))

base_bin = "11001000010101001000100011001000110010000110100011101010011110110110001001001111001000010110000101110011101011011101011001001011110100011000111100101110000100101001111001111011110111101001110100101100110101111101101110101111001000111100111000000100101001101000001101010111101010010100000101010001010010010100101111011101111100110010101000100000001101000011101001011111101001100110111001000000110110101010111100100101111110111010011110001000011011010010110000000011111100001100"

final___ = "11010011010000101111101110101001011001101100101000111101101110101101010000010111101110000110100001000111101100000001110010010000000001011111001101111110011110111100111000111111101000110110010111100111110001111010110100110111000001001111010001100110111000101010010001000110010001100100001101000111010100111101101100010010011110010000101100001011100111010110111010110010010111101000110001111001011100001001010011110011110111101111010011101001011001101011111011011101011110010001"

pwd = ['A']*33

pwd[0] = 'j'
pwd[1] = 'u'
pwd[2] = 's'
pwd[3] = 't'
pwd[4] = 'C'
pwd[5] = 'T'
pwd[6] = 'F'
pwd[7] = '{'
pwd[-1] = '}'

pwd_charset = ""
for i in range(len(pwd)):

    index = charset.index(pwd[i])
    i_l = index * 7
    i_h = (index+1)*7
    blob = charset_bin[i_l:i_h]
    pwd_charset += blob

x = 33*7
base_bin_x = base_bin[x:] + base_bin[:x] 

flag = ""
for i in range(len(pwd_charset)):

    v1 = int(pwd_charset[i])
    v2 = int(base_bin_x[i])

    if v1 == v2:
        r = 0
    else:
        r= 1

    if i==62:
        pass

    #oui c'est sale
    if r != int(final___[i]):
        if r:
            flag += base_bin_x[i]
        else:
            if int(base_bin_x[i]):
                flag += '0'
            else:
                flag += '1'
    else:
        flag += pwd_charset[i]

#simple check pour vérifier on est bon
for i in range(len(flag)):

    v1 = int(flag[i])
    v2 = int(base_bin_x[i])

    if v1 == v2:
        r = 0
    else:
        r= 1

    if r != int(final___[i]):
        print(r, int(final___[i]), i)
        raise Exception("SHOULD NOT FAIL")

print("flag=", flag)
fflag = ""
for x in range(0, len(flag), 7):
    ax = flag[x:x+7]
    for i in range(0, len(charset)):
        a1 = i*7
        a2 = (i+1)*7
        p1 = charset_bin[a1:a2]
        print(ax, p1, charset[i])
        if ax == p1:
            fflag += charset[i]

print(fflag) #justCTF{0ld_TV_c4n_b3_InTeR4ctIv3}
```

Et voila !
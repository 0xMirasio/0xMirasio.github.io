---
layout: post
title: ImaginaryCTF 2024 - Printf
subtitle: format string vulnerability vm
tags: [reverse, vm, formatstring]
comments: true
---

### ImaginaryCTF 2024 - SVM Revenge

!["Main"](/assets/img/posts/imaginaryctf2024/printf.png "Description")


On nous fournit un binaire : `printf` ainsi que une libc `libc.so.6`

# Analyse du binaire

!["Main"](/assets/img/posts/imaginaryctf2024/printf_main.png "main()")

Hmmm... Voyons voir ce format qui a l'air intriguant...


!["Main"](/assets/img/posts/imaginaryctf2024/printf_main2.png "format string payload")

Bon, nous avons donc un programme qui utilise une gigantesque format string pour écraser de la mémoire et setup un flag checker. 

analysons sur gdb son comportement : 

!["Main"](/assets/img/posts/imaginaryctf2024/printf_gdb.png "gdb")

Donc après le printf, on va jump dans les internals de la libc, puis après qu'il écrit certaines valeurs, il va revenir dans le binaire de base pour repasser ensuite dans la libc.

En suivant, on remarque qu'il fait ça quasiment tout le long...

analysons donc les fonctions du programme : 

!["Main"](/assets/img/posts/imaginaryctf2024/printf_handler.png "vm handler")

On remarque que certaines fonctions sont appelé de manière regulière, toute initialisé via cette fonction. La plupart de ces fonctions utilise une zone mémoire pour faire leur opérations + un dword sert de compteur pour positionner les opérations sur la mémoire. Cela nous fait penser à une VM... 

!["Main"](/assets/img/posts/imaginaryctf2024/printf_meme.jpg "oui")

Bon comme d'habitude, créeons un script gdb pour dump l'entièreté des opérations de la VM pour suivre son activité...

```py
import gdb
import os
import sys
import ctypes

gdb.execute("file printf_patched")
gdb.execute("d")

opcode = {
    0 : "getchar",
    1 : "putchar",
    2 : "set_1",
    3: "vm_add",
    4 : "vm_xor",
    5 : "vm_minus",
    6 : "vm_mul",
    7 : "vm_div",
    8 : "vm_mod",
    9 : "vm_exit",
    10 : "set_2",
    11 : "set_3"
}

class Logger():
    def __init__(self, char=None):
        if char:
            self.ppath = f"output/vm_log_{ord(char)}.txt"
        else:
            self.ppath = "vm_log.txt"
        if os.path.exists(self.ppath):
            os.remove(self.ppath)
        self.fd = open(self.ppath, "w")

    def log(self, entry:str, silent:bool=False):
        self.fd.write(entry + "\n")
        if silent:
            print(entry)    
        self.fd.flush()

    def __del__(self):
        if self.fd:
            self.fd.close()

logger = Logger()

def to_int(gdb_v:gdb.Value):
    return ctypes.c_uint64(gdb_v.cast(gdb.lookup_type('long long'))).value

def try_str(v) -> str:
    return v.to_bytes(8, byteorder="little").replace(b"\x00",b"")
class VMDecoder(gdb.Breakpoint):
    
    def __init__(self, bp, opcode):
        super().__init__(bp)
        self.opcode = opcode
    def stop(self):
        opcode_str = opcode[self.opcode]
        #DATA
        rax = to_int(gdb.parse_and_eval("(uint64_t *)$rax"))
        rdi = to_int(gdb.parse_and_eval("(uint64_t *)$rdi"))
        al = to_int(gdb.parse_and_eval("(uint64_t *)$al"))
        rcx = to_int(gdb.parse_and_eval("(uint64_t *)$rcx"))
        rdx = to_int(gdb.parse_and_eval("(uint64_t *)$rdx"))

        #MAIN
        try:
            match self.opcode:
                case 0:
                    logger.log(f"{opcode_str} | {hex(rax)}|{try_str(rax)}", silent=True)
                case 4:
                    logger.log(f"{opcode_str} | {hex(rcx)} ^ {hex(rax)} ={hex(rcx^rax)}", silent=True)
                case 1:
                    pass
                    logger.log(f"{opcode_str} | {hex(al)}|{try_str(al)}")
                case 3:
                    logger.log(f"{opcode_str} | {hex(rcx)}+{hex(rax)}={hex(ctypes.c_uint64(rcx+rax).value)}", silent=True)
                
                case 5:
                    logger.log(f"{opcode_str} | {hex(rax)} - {hex(rcx)} ={hex(rcx-rax)}")
                case 6:
                    logger.log(f"{opcode_str} | {hex(rax)} * {hex(rdx)} ={hex(ctypes.c_uint64(rdx*rax).value)}", silent=True)
                case 7:
                    logger.log(f"{opcode_str} | / {hex(rcx)}")
                case 8:
                    logger.log(f"{opcode_str} | % {hex(rcx)}")
                case 9:
                    logger.log(f"{opcode_str}")
                case 10:
                    logger.log(f"{opcode_str} | = {hex(rax)})")
                    pass
                case 11:
                    logger.log(f"{opcode_str} | = {hex(rax)})")
                    pass
                case 2:
                    logger.log(f"{opcode_str} | {hex(rax)}")
                    pass
        except Exception as e:
            logger.log(f"{opcode_str} | =error")
        return False
    

cpt_addr = 0x555555570040

bp = VMDecoder("*0x5555555551DE", 0)
bp = VMDecoder("*0x555555555642", 4)
bp = VMDecoder("*0x55555555520A", 1)
bp = VMDecoder("*0x55555555532F", 2)
bp = VMDecoder("*0x55555555539D", 3)
bp = VMDecoder("*0x555555555422", 5)
bp = VMDecoder("*0x5555555554A9", 6)
bp = VMDecoder("*0x55555555554A", 7)
bp = VMDecoder("*0x5555555555D4", 8)
bp = VMDecoder("*0x555555555688", 9)
bp = VMDecoder("*0x555555555250", 10)
bp = VMDecoder("*0x5555555552C3", 11)


import string
charset = string.printable[0:len(string.printable)-10]
flag = [0x42]*30
flag[0] = ord('i')
flag[1] = ord('c')
flag[2] = ord('t')
flag[3] = ord('f')
flag[4] = ord('{')
flag[5] = ord('B')
flag[-1] = ord('}')

ct = {}

offset=5
charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!? "

flag = "ictf{AAA"

gdb.execute(f"r <<< '{flag}'")
```
Après quelque minutes de lecture de logs, nous comprenons l'essentiel de la vm : 

```
getchar | 0x41|b'A' #la vm récupère un octet du flag
set_2 | = 0x9920dd9
set_2 | = 0x342e70ab00000000
vm_add | 0x342e70ab00000000+0x9920dd9=0x342e70ab09920dd9
set_1 | 0x342e70ab00000000
set_1 | 0x9920dd9
set_3 | = 0x342e70ab09920dd9
set_2 | = 0x2
set_2 | = 0x40000000
vm_mul | 0x2 * 0x40000000 =0x80000000
set_1 | 0x40000000
set_1 | 0x2
set_3 | = 0x80000000
vm_add | 0x80000000+0x342e70ab09920dd9=0x342e70ab89920dd9
set_1 | 0x80000000
set_1 | 0x342e70ab09920dd9
set_3 | = 0x342e70ab89920dd9
vm_mul | 0x41 * 0x342e70ab89920dd9 =0x3fca9b8dee158419 #on multiplie l'octet avec une clé
set_1 | 0x342e70ab89920dd9
set_1 | 0x41
set_3 | = 0x3fca9b8dee158419 #cette clé sera utilisé juste après
```
La même opération est faite avec 3 autres octets puis : 
```
vm_add | 0x6c4679ef8fab033e+0xe34c9681fa0ee02a=0x4f93107189b9e368 #on additionne octet1*clé1 + octet2*clé2
set_1 | 0x6c4679ef8fab033e
set_1 | 0xe34c9681fa0ee02a
set_3 | = 0x4f93107189b9e368
vm_add | 0x4f93107189b9e368+0x2bc8c3571adf8a31=0x7b5bd3c8a4996d99 #idem mais avec le résultat précédent + octet3*clé3 
set_1 | 0x4f93107189b9e368
set_1 | 0x2bc8c3571adf8a31
set_3 | = 0x7b5bd3c8a4996d99
vm_add | 0x7b5bd3c8a4996d99+0x3fca9b8dee158419=0xbb266f5692aef1b2 #etc...
set_1 | 0x7b5bd3c8a4996d99
set_1 | 0x3fca9b8dee158419
set_3 | = 0xbb266f5692aef1b2
set_3 | = 0x9d29cb475e41cb8f
vm_xor | 0x9d29cb475e41cb8f ^ 0xbb266f5692aef1b2 =0x260fa411ccef3a3d # on xor le tout avec une clé. Si la valeur xoré avec un valuer stocké en mémoire est égale à 0, on continue, sinon on quitte 
```

Donc, nous avons 4 octets par 4octets testé dans la VM, avec 4 clé qui sert de multiplicateur avec l'octet, puis chaque résultat est additionné pour être xoré avec une clé, vérifié avec une autre.

On peut donc juste récupérer le flag 4 octets par 4 dans un script. (j'ai pas voulu dumper toute les clés, j'ai fait à la main, ça prenais - de 20s pour 4octets)

```py
import ctypes
import sys

#important, la multiplication fait overflow les entiers, donc il faut absolument setup sur 64bit.
a1,a2,a3,a4 = ctypes.c_uint64(0),ctypes.c_uint64(0),ctypes.c_uint64(0),ctypes.c_uint64(0)

charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_!? " + '}{'

# tous est dump depuis vm_log.txt (change tout les 4octets)
k1 = 0xf9923bc7ae594205 
k2 = 0x97b9f4f4c11b13ee
k3 = 0x2452efbf17fce49
k4 = 0x7b75687e9288270a

K= 0x54ccfb02994249cf
K2 = 0xcfae6899f240f30a

# ~30S avec le charset
for c1 in charset:
    print(c1)
    for c2 in charset:
        for c3 in charset:
            for c4 in charset:

                cc1 = ord(c1)
                cc2 = ord(c2)
                cc3 = ord(c3)
                cc4 = ord(c4)

                c1x = ctypes.c_uint64(cc1 * k1).value
                c2x = ctypes.c_uint64(cc2 * k2).value
                c3x = ctypes.c_uint64(cc3 * k3).value
                c4x = ctypes.c_uint64(cc4 * k4).value

                p1 = ctypes.c_uint64(c4x + c3x).value
                p2 = ctypes.c_uint64(p1 + c2x).value
                p3 = ctypes.c_uint64(p2 + c1x).value

                f = p3 ^ K

                if f == K2:
                    print(c1,c2,c3,c4)
                    sys.exit(0)
```

on obtient donc à la fin :
`ictf{n3v3r_too_m4ny_form4t_sp3cifi3rs_9a7837294d1633140433f51d13a033736}"`
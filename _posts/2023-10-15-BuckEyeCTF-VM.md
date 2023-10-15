---
layout: post
title: Writeup BuckeyeCTF Belt1
subtitle: This need to stop
tags: [reverse, VM, gdb]
comments: true
---

# Challenge

Ce challenge provient du BuckeyeCTF 2023. 
ENCORE une fois, nous allons affronter une VM (stop it) écrite en Rust (Yes)

## Analyse du binaire

Nous avons dans belt::main() un dispatcher d'opcode.
(tips : utiliser IDARustDemangler pour simplifier le rev)

Nous trouvons rapidement 15 opcodes dont les fonctions sont plus au moins approximatives (certain évident : printf, exit, assign to mem, get from mem, ...)
Nous constatons également l'utilisation d'une mémoire dans la VM ainsi que des registres virtuels

Voici un début de parser du fichier fourni contenant les opcodes/valeurs du challenges : 

```python
opcode = {
    0 : "mem[index] = r1",
    1 : "testSize",
    2 : "2?",
    0x10 : "incrementIndex",
    0x12: "0x12?",
    0x20 : "0X20? assign to queue?",
    0x21 : "0X21? assign to queue?",
    0x22 : "0X22? assign to queue?",
    0x23 : "0X23? assign to queue?",
    0x24 : "0X24? assign to queue?",
    0x40 : "print()",
    0x41 : "print(lowHex())",
    0x42 : "readline()",
    0x43 : "readlineAsHex()",
    0x50 : "exit()",

}

fd = open("flag_checker","rb")
data=  fd.read()
rdata= ""
cpt = 0
while cpt < len(data):

    value = None
    byte = data[cpt]

    if byte == 0:
        value = data[cpt+1]
        rdata += chr(value)

        cpt += 1
        
    print(byte , opcode[byte], value)
    cpt += 1

print(rdata)

```

Je ne souhaite pas perdre 3h à analyser les opcodes et ayant fait 4 challenges de VM les 3 dernières semaines, j'ai vite décidé de skip cette partie.
Bien, il n'y a pas de strcmp ou autre opcode qui pourrait faire un test du mot de passe.
Cependant, l'op code 0x10 est particulierement intéréssant car il va tester une valeur de la mémoire et incrémenter l'index de la position du fichier en fonction
C'est très intéréssant car c'estr un moyen de tester un mot de passe, si le pointeur va dans une zone du fichier au lieu d'une autre, il éxecute différents opcodes.

Je vais donc immédiatement sur gdb pour tester et voir si les bytes du mot de passe sont utilisé pour ce test la.

Voici la template utilisé dans python : 

```python
opcode = {
    0 : "mem[index] = r1",
    1 : "testSize",
    2 : "2?",
    0x10 : "TestFlag => incrementIndex",
    0x12: "0x12?",
    0x20 : "0X20? assign to queue?",
    0x21 : "0X21? assign to queue?",
    0x22 : "0X22? assign to queue?",
    0x23 : "0X23? assign to queue?",
    0x24 : "0X24? assign to queue?",
    0x40 : "print()",
    0x41 : "print(lowHex())",
    0x42 : "readline()",
    0x43 : "readlineAsHex()",
    0x50 : "exit()",

}

import gdb

cpt=0
bl = None
index = None

gdb.execute("file ./belt")
gdb.execute("d")

data = ""

class VMDecoder(gdb.Breakpoint):
    def __init__(self, bp, opcode):
        super().__init__(bp)
        self.opcode = opcode

    def stop(self):
            
            dp = [0, 1, 2, 36, 0x21, 0x42]
            
            global fd
            global cpt
            global index_
            global index


            if self.opcode == 1:
                index = int(gdb.parse_and_eval("$rax"))
                bl = int(gdb.parse_and_eval("(unsigned char)$bl"))
                    
            if self.opcode == 0:
                index = gdb.parse_and_eval("$rcx")
                bl = gdb.parse_and_eval("(unsigned char)$bl")
                if int(bl) != 0:
                    print(f"[0] Set queue[{int(index)}] = {hex(bl)} ({chr(int(bl))})")
                else:
                    print(f"[0] Set queue[{int(index)}] = 0")

            
            if self.opcode == 36:
                index = gdb.parse_and_eval("$rax")
                bl = gdb.parse_and_eval("(unsigned char)$bl")
                if int(bl) != 0:
                    print(f"[0x24] (~&) Set queue[{int(index)}] = {hex(bl)} ({chr(int(bl))})")
                else:
                    print(f"[0x24] (~&) Set queue[{int(index)}] = 0")


            if self.opcode == 0x21:
                index = gdb.parse_and_eval("$rax")
                bl = gdb.parse_and_eval("(unsigned char)$bl")

                if int(bl) != 0:
                    print(f"[0x21] (-) Set queue[{int(index)}] = {hex(bl)} ({chr(int(bl))})")
                else:
                    print(f"[0x21] (-) Set queue[{int(index)}] = 0")

            return False #gdb.continue()
      

gdb.execute("file belt")
gdb.execute("d")

readline = VMDecoder("*0x000055555555E0F2", 66)
oP2 =  VMDecoder("*0x000055555555E2D3", 2)
testflag = VMDecoder("*0x55555555ecd6", 0x10)
exit =VMDecoder("*0x000055555555EEE6", 80)

oP3 =  VMDecoder("*0x000055555555E09E", 65)
oP4 =  VMDecoder("*0x000055555555E177", 64)
oP5 =  VMDecoder("*0x000055555555E1A1", 35)
oP6 =  VMDecoder("*0x000055555555EE87", 36)
oP7 =  VMDecoder("*0x000055555555E2A9", 32)
oP8 =  VMDecoder("*0x000055555555E321", 34)
oP9 =  VMDecoder("*0x000055555555E1CB", 67)
oP10 =  VMDecoder("*0x000055555555E27F", 18)
oP11 =  VMDecoder("*0x000055555555EE87",33)
oP13 =  VMDecoder("*0x000055555555EE87", 1)

op0 =  VMDecoder("*0x000055555555E93F", 0)

```

En effet, en suivant chaque opcode sur gdb, on retrouve plusieurs opérations arithmétiques basiques par octets du mot de passe suivi de ce test. 
Il n'est pas nécéssaire de dumper chaque opération de la VM mais cela donne un apercu
On peut donc essayer de break sur cette opcode, et bruteforcer octet par octet.

ce qui donne comme script de résolution : 

```python


opcode = {
    0 : "mem[index] = r1",
    1 : "testSize",
    2 : "2?",
    0x10 : "TestFlag => incrementIndex",
    0x12: "0x12?",
    0x20 : "0X20? assign to queue?",
    0x21 : "0X21? assign to queue?",
    0x22 : "0X22? assign to queue?",
    0x23 : "0X23? assign to queue?",
    0x24 : "0X24? assign to queue?",
    0x40 : "print()",
    0x41 : "print(lowHex())",
    0x42 : "readline()",
    0x43 : "readlineAsHex()",
    0x50 : "exit()",

}



import gdb

cpt=0
bl = None
index = None

gdb.execute("file ./belt")
gdb.execute("d")

data = ""

class VMDecoder(gdb.Breakpoint):
    def __init__(self, bp, opcode):
        super().__init__(bp)
        self.opcode = opcode

    def stop(self):
            
            dp = [0, 1, 2, 36, 0x21, 0x42]
            
            global fd
            global cpt
            global index_

            global bl
            global index
            global found


            if self.opcode == 0x10:
                
                
                index = int(gdb.parse_and_eval("$rax"))
                bl = int(gdb.parse_and_eval("(unsigned char)$bl"))
                cpt += 1

                
                if (cpt == index_ +1 ):
                    print("should be 0 for win => bl= ", bl)
                    print(cpt, index_ + 1)
                    if bl == 0:
                        found=True
                        return False
                    
            
            return False
      

gdb.execute("file belt")
gdb.execute("d")


readline = VMDecoder("*0x000055555555E0F2", 66)
oP2 =  VMDecoder("*0x000055555555E2D3", 2)
testflag = VMDecoder("*0x55555555ecd6", 0x10)
exit =VMDecoder("*0x000055555555EEE6", 80)

oP3 =  VMDecoder("*0x000055555555E09E", 65)
oP4 =  VMDecoder("*0x000055555555E177", 64)
oP5 =  VMDecoder("*0x000055555555E1A1", 35)
oP6 =  VMDecoder("*0x000055555555EE87", 36)
oP7 =  VMDecoder("*0x000055555555E2A9", 32)
oP8 =  VMDecoder("*0x000055555555E321", 34)
oP9 =  VMDecoder("*0x000055555555E1CB", 67)
oP10 =  VMDecoder("*0x000055555555E27F", 18)
oP11 =  VMDecoder("*0x000055555555EE87",33)
oP13 =  VMDecoder("*0x000055555555EE87", 1)

op0 =  VMDecoder("*0x000055555555E93F", 0)

flag_ = ['A']*29
count = 0

flag_[0] = "b"
flag_[1] = "c"
flag_[2] = "t"
flag_[3] = "f"
flag_[4] = "{"

import string

ptr = string.printable[0:len(string.printable)-5] + '0_'

# got some bugs with caracters here , not really good script
for i in range(23,len(flag_)):
    index_= i
    for char in ptr:


        found=False
        flag_[len(flag_)-index_ - 1] = char

        flag = ''.join(flag_)
        print(f'Trying {flag}')

        args = ""
        for i in range(len(flag)):
            args += flag[i] + "\n"

        fd = open("input","wb")
        fd.write(args.encode())
        fd.close()

        cmd = f"r flag_checker < input"
        gdb.execute(cmd)

        if found:
            print("found a valid char : " + char)
            flag_[len(flag_)-index_ - 1] = char
            print(''.join(flag_))
            break
        

        cpt = 0


print(''.join(flag_))

```

On obtient donc le flag de validation (après quelque temps, le script a pas mal buggé et gdb est très lent) : 

---
layout: post
title: Writeup DUCTF MsFlagChecker
subtitle: z3 time
tags: [reverse]
comments: true
---

# Challenge

Ce challenge provient du DUCTF 2023.

## Analyse du binaire

Après un premier coup basique de angr avec les strings "Correts" / "Incorrect!", je me rend compte rapidement que angr ne pourra pas résoudre le chall : 

```c 
__int64 __fastcall checkpass(char *buf1, char *buf2)
{
  __int64 cpt1; // rdx
  unsigned int ret; // ecx
  __int64 cpt2; // rax

  cpt1 = 24LL;
  ret = 0;
  do
  {
    cpt2 = cpt1 - 24;
    do
    {
      if ( *(_DWORD *)&buf2[cpt2] )
        ret += *(_DWORD *)&buf1[cpt2];
      cpt2 += 4LL;
    }
    while ( cpt2 != cpt1 );
    cpt1 += 24LL;
  }
  while ( cpt1 != 168 );
  return ret;
}
```

Ici une somme est renvoyé, elle est incrémenté avec le l'octet du mot de passe à la position cpt2. 
Donc on passe un vecteur (buf2) à la fonction, et si dans le vecteur le bit est à 1, alors on incrémente la somme retourné avec un octet du mdp.
Concretement, cela va kill tout espoir d'angr ou autre car la complexité de résolution est bien trop grosse.

Par contre, cette fonction est appelé 26 fois, avec des vecteurs dont le bit à 1 correspond à un offset du mot de passe. on peut donc faire un systèmes d'équations que l'ont peut résoudre dans z3.

# récupération des vecteurs & résultats testés.

Pour commencer, il faut récuperer le vecteur buf2 * 26 fois. 

On peut utiliser un script gdb qui va break dans le ret += buf1[cpt2] et récup sa position.
De même, on peut break dans le test de la valeur de retour de checkpass() pour récuperer les valeurs qui seront testés.

faire **gdb msflagchecker**
puis **source getvector.py**


```python
import gdb

totest= []
map_vector = []
sub_map_vector = []

old_rax = 0

#on récupère les valeurs accumulatives qui seront testées
class BreakpointHandler(gdb.Breakpoint):
    def stop(self):
        eax_value = gdb.parse_and_eval("$eax")
        #print(f"Value of eax: {eax_value}")

        rbp_value = gdb.parse_and_eval("*(int *)$rbp")
        #print(f"Value at [rbp]: {rbp_value}")
        gdb.execute(f"set $eax = {rbp_value}")
        totest.append(f"{eax_value}")
          
        return False # gdb.continue()
    
#on récupère le vecteur X de l'itération i
class GetTestMap(gdb.Breakpoint):
    def stop(self):

        global sub_map_vector
        rax = gdb.parse_and_eval("$rax")
        
        rax_str = f"{rax}"
        rax_ = int(rax_str)//4
        sub_map_vector.append(rax_)
    
        return False  # Continue execution
    
#detecte si on passe au prochain vecteur, si rdx == 0xa8, check_pass va se terminer
class ResetVectorMap(gdb.Breakpoint):
    def stop(self):

        global sub_map_vector
        global map_vector
        rdx = gdb.parse_and_eval("$rdx")
        
        if rdx == 0xa8:
            map_vector.append(sub_map_vector)
            sub_map_vector = []

        return False  # Continue execution
          

gdb.execute("file ms_flag_checker")
gdb.execute("d")

bp = BreakpointHandler("*0x5555555552f1") #test checkpass() == valeur_mem
bp2 = GetTestMap("*0x0000555555555232")
bp3 = ResetVectorMap("*0x000055555555523B")

flag = ['A']*36
flag_ = ''.join(flag)
print("Will try : ", flag_)
```

on peut alors récuperer les valeurs des vecteurs. 

# Resolution

Il suffit ensuite de faire un script z3 qui écrit le système d'équations, prendre un café et hop le flag.

```python
vector = [[5, 8, 10, 11, 12, 16, 17, 19, 21, 23, 25, 26, 30, 31, 34, 35], [1, 5, 6, 10, 11, 13, 16, 17, 18, 20, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32, 34, 35], [1, 3, 5, 6, 8, 15, 17, 20, 22, 24, 29, 30, 31, 33], [0, 1, 3, 4, 5, 6, 7, 11, 12, 13, 15, 16, 17, 18, 20, 21, 23, 24, 25, 26, 27, 31, 32], [1, 5, 7, 10, 12, 13, 14, 16, 18, 21, 22, 23, 24, 25, 27, 28, 29, 30, 32], [0, 3, 4, 13, 21, 22, 24, 28, 31], [21], [2, 3, 4, 9, 10, 11, 12, 18, 21, 23, 26, 29, 31, 32, 33, 34], [4, 5, 6, 7, 8, 12, 18, 22, 25, 26, 27, 28, 29, 34, 35], [1, 2, 7, 9, 10, 11, 12, 16, 21, 23, 24, 26, 30, 32, 33], [2, 11, 13, 17, 19, 27], [0, 3, 4, 5, 6, 7, 9, 18, 19, 20, 23, 26, 30, 35], [3, 13, 16, 34], [0, 1, 2, 8, 9, 10, 11, 13, 16, 18, 19, 23, 24, 25, 27, 29, 30, 31, 33, 34], [2, 3, 7, 9, 11, 13, 21, 23, 24, 25, 26, 27, 28, 30, 31, 32, 34], [0, 6, 9, 10, 12, 13, 15, 17, 23, 25, 27, 28, 29, 30, 31], [0, 1, 5, 11, 12, 13, 14, 17, 18, 19, 22, 23, 24, 25, 26, 28, 29, 31, 32, 34, 35], [1, 5, 7, 8, 11, 13, 14, 15, 16, 17, 18, 19, 22, 23, 24, 26, 27, 28, 29, 31, 34], [0, 1, 3, 6, 7, 9, 10, 13, 14, 15, 16, 17, 19, 21, 22, 26, 27, 29, 32, 33, 35], [0, 4, 5, 6, 8, 11, 13, 14, 15, 16, 17, 18, 20, 22, 23, 26, 28, 30, 31, 32, 34, 35], [9, 19, 25], [0, 2, 3, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 28, 29, 32, 35], [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 22, 24, 27, 31], [2, 6, 8, 9, 15, 16, 17, 18, 19, 20, 22, 23, 26, 27, 28, 29, 31], [2, 7, 9, 12, 16, 20, 24, 25, 26, 33], [8, 9, 10, 11, 14, 15, 17, 18, 19, 25, 28, 29, 31]]
totest= ['1441', '2043', '1259', '2031', '1799', '746', '55', '1450', '1485', '1362', '611', '1314', '358', '1834', '1500', '1355', '2011', '1990', '1939', '1990', '278', '1859', '2111', '1510', '888', '1224']

assert(len(vector) == 26)
assert(len(totest) == 26)


import z3

solver = z3.Solver()
x = z3.BitVec('x', 36*8)

bytes_list = [z3.Extract((i+1)*8-1, i*8, x) for i in range(36)]
solver.add(bytes_list[0] == ord('D'))
solver.add(bytes_list[1] == ord('U'))
solver.add(bytes_list[2] == ord('C'))
solver.add(bytes_list[3] == ord('T'))
solver.add(bytes_list[4] == ord('F'))
solver.add(bytes_list[5] == ord('{'))
solver.add(bytes_list[35] == ord('}'))


alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

allowed_ascii_values = [ord(char) for char in alphabet]

for i in range(6,35):
    solver.add(z3.Or([bytes_list[i] == value for value in allowed_ascii_values]))

for eq_vector, total in zip(vector, totest):
    equation = z3.Sum([bytes_list[i] for i in eq_vector]) == int(total)
    solver.add(equation)

import binascii

if solver.check() == z3.sat:
    solution = solver.model()[x]
    extracted_bytes = [solution.as_long() >> (i*8) & 0xFF for i in range(36)]
    
    print("flag = ", ''.join(chr(i) for i in extracted_bytes))

else:
    print("No solution found.")
```

On obtient : DUCTF{ezzzpzzz_07bcda7bfe81faf43caa} 

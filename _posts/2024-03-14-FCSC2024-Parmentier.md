---
layout: post
title: FCSC 2024 CTF - Parmentier
subtitle: secure db
tags: [reverse, parsing]
comments: true
---

### FCSC 2024 CTF - Parmentier

!["Main"](/assets/img/posts/fcsc2024/b1.png "Description")

On nous fournit un binaire parmentier ainsi qu'un fichier export.pdt qui est une db custom.
La db du programme se base sur un dictionnaire -> key:value

!["Main"](/assets/img/posts/fcsc2024/b2.png "main")

Le main() du programme est relativement simple, c'est un menu interactif ou l'ont peut choisir les actions suivantes:

- Obtenir une clé de la DB (et afficher sa valeur)
- set une clé
- exporter la DB
- importer une DB (pas implem)
- Exit

# Analyse de l'algo

!["Main"](/assets/img/posts/fcsc2024/b3.png "getkey")


Le placement des noms de clés et leur valeur en mémoire est déterministe, il dépend d'une clé aléatoire généré au début, et suit un placement qui est calculé selon des index.

Ici dans getkey(), un id est dérivé de nom de la clé voulu, puis la db est parsé jsuqu'a ce que le nom soit trouvé. On notera que id est encore dérivé si jamais le nom n'est pas trouvé directement.
Un 2ème id (id_kval) est alors généré en fonction de l'id actuel du nom de la clé, ce qui donne la position en mémoire de la valeur de la clé, qui sera renvoyé.

setkey() marche pratiquement de la même manière.

# Analyse de l'export

!["Main"](/assets/img/posts/fcsc2024/b4.png "export_db")

L'export de la DB suit les règles suivantes: 

- Header PRMT (4 octets)
- db->nb_key_max (4octets) (le nombre de clé maximum de la db, calculé à chaque fin d'itération du menu interactif, une reallocation est faite si des clés sont set et plus d'espace est requis)
- db->nb_key_real (4octets) : le nombre de clé actuelle de la db
- db->key : la clé de 8octets généré aléatoirement au début

Le programme va ensuite exporter l'information suivante:

Pour le nombre de clé max >> 3, on test si la clé existe (8 fois car chaque clé = Max 8 octets)
si la clé existe en mémoire, un chiffre est shifté à droite de la valeur de j

Cette information est très importante car elle va pouvoir permettre de reconstituer la DB.
Si nous disposons d'une liste de toutes les clés de la DB, nous ne saurons pas ou elle sont placés de manière deterministe en mémoire.

On peut utiliser cette petite boucle pour retrouver leur position en mémoire:
```python
newPMname = [0]*(8*(pm.nb_key_max))

cx = 0
for i in range(len(pm.r1)):
    v3 = pm.r1[i]
    for j in range(8):
        if v3 >> j & 1:
            vname = ParmentierDB.byte2vec(pm.all_dbname[cx])
            for h in range(len(vname)):
                newPMname[64*i + 8*j + h] = vname[h]
            cx += 1
    

pm.dbnameVEC = newPMname
```

Juste après, les noms de clés sont exportés dans le fichier de sortie. 

Il est ensuite fait la même chose avec les valeurs des clés : une première boucle shiftant un nombre en fonction de la position des valeurs de clé puis un dump de toute les valeurs de clés...

# Resolution

Une petit xxd de la db montre des faux flags de partout, mais en regardant les différentes clés dispo : on retoruve la clé 'flag', il faut donc juste recréer la db en mémoire, calculer le bon index et retrouver le flag associé : 

```python
import sys
if sys.argv[1] == "1":
    db = open("export.pdt.bak","rb")
else:
    db = open("test.pdt","rb")
import struct
magic = db.read(4)
assert(magic == b'PRMT')

import ctypes

nb_key_max = struct.unpack("<I", db.read(4))[0]
nb_key = struct.unpack("<I", db.read(4))[0]
key = struct.unpack("<Q", db.read(8))[0]

print(nb_key)

def H(v):
    return hex(v.value)

def pprint(list):
    r = ""
    for i in range(len(list)):
        v = list[i]
        if v==0:
            r += "."
        else:
            r += chr(v)

    print(r)

class ParmentierDB(object):
    def __init__(self, fd, key, nb_key_max, nb_key_real):
        self.fd = fd
        self.key = key
        self.nb_key_max = nb_key_max
        self.nb_key_real = nb_key_real

        self.dbnameVEC = [0]*(8*(nb_key_max))
        self.dbvalueVEC = [0]*((1 << 10) * (nb_key_max))

        self.all_dbname = []
        self.all_dbvalue = []

        self.r1 = []
        self.r2 = []
        
    def read_string(self):
        r = b""
        while True:
            v = self.fd.read(1)
            if v == b"\x00":
                return r + b"\x00"
            else:
                r += v

    @staticmethod
    def int2Vec(id:ctypes.c_uint64):
        r = id.value
        z = r.to_bytes(8, byteorder="little")

        ret = [0]*8
        for h in range(8):
            ret[h] = z[h] 
        return ret
        
    @staticmethod
    def str2vec(name:str):
        name_pf = [0]*8
        for i in range(len(name)):
            name_pf[i] = ord(name[i])
        return name_pf
    
    @staticmethod
    def byte2vec(name:bytes):
        name_pf = [0]*len(name)
        for i in range(len(name)):
            name_pf[i] = name[i]
        return name_pf
       

    def read_r(self, target):
        for _ in range(self.nb_key_max >> 3):
            target.append(struct.unpack("<B", self.fd.read(1))[0])

    def get_all_dbname(self):
        for _ in range(self.nb_key_real):
            dbname = db.read(8)
            self.all_dbname.append(dbname)

    def get_all_dbvalue(self):
        for _ in range(self.nb_key_real):
            dbvalue = self.read_string()
            self.all_dbvalue.append(dbvalue)

    def kval(self, id:ctypes.c_uint64):
        r = ctypes.c_uint64(0)
        r.value = 0x100000001B3 * (self.key + id.value)
        return r.value
    
    def get_id_from_keyname(self, name:list):
        id = ctypes.c_uint64(0xCBF29CE484222325)
        vtemp = ctypes.c_uint64(0)
        for i in range(8):
            vtemp.value = (self.key + (name[i] ^ id.value))
            id.value = 0x100000001B3 * vtemp.value

        return id
    
    def fill_db(self):

        id_kval =ctypes.c_uint32(0)
        
        for dbname_b in self.all_dbname:
            dbname = dbname_b.replace(b"\x00",b"").decode()
            id = self.get_id_from_keyname(ParmentierDB.str2vec(dbname))
            index = id.value & (self.nb_key_max -1)
            vindex = index << 3
            if (self.dbnameVEC[vindex] != 0):
                id = self.get_id_from_keyname(ParmentierDB.int2Vec(id))
            else:
                self.dbnameVEC[vindex:vindex+8] = dbname_b
                id_kval.value = self.kval(id) & (self.nb_key_max - 1)
                assert(self.dbvalueVEC[id_kval.value] == 0)
                """#TEST
                toFill = [0]*1024
                tdataTest = dbname + "value"
                for h in range(len(tdataTest)):
                    toFill[h] = ord(tdataTest[h])
                self.dbvalueVEC[id_kval.value:id_kval.value + 1024] = toFill"""


    def get_id_key(self, name):
        id_kval =ctypes.c_uint32(0)
        id = self.get_id_from_keyname(ParmentierDB.str2vec(name))
        while True:
            index = id.value & (pm.nb_key_max -1)
            vindex = index << 3
            if self.dbnameVEC[vindex] != 0:
                dbX = self.dbnameVEC[vindex:vindex+8]
                dbname = ''.join(chr(v) for v in dbX).replace("\x00","")
                if dbname == name:
                    id_kval.value = self.kval(id) & (self.nb_key_max - 1)
                    return id_kval.value
                else:
                    id = self.get_id_from_keyname(ParmentierDB.int2Vec(id))

            else:
                raise Exception("dunnow")
            
    def get_key(self, name):
        id_kval =ctypes.c_uint32(0)
        id = self.get_id_from_keyname(ParmentierDB.str2vec(name))
        while True:
            index = id.value & (pm.nb_key_max -1)
            vindex = index << 3
            if self.dbnameVEC[vindex] != 0:
                dbX = self.dbnameVEC[vindex:vindex+8]
                dbname = ''.join(chr(v) for v in dbX).replace("\x00","")
                if dbname == name:
                    print(f"found entry, id={H(id)}")
                    id_kval.value = self.kval(id) & (self.nb_key_max - 1)
                    index = id_kval.value << 10
                    return self.dbvalueVEC[index:index+1023]
                else:
                    id = self.get_id_from_keyname(ParmentierDB.int2Vec(id))

            else:
                raise Exception("dunnow")
            
pm = ParmentierDB(db, key, nb_key_max, nb_key)
pm.read_r(pm.r1)
pm.get_all_dbname()
pm.read_r(pm.r2)
pm.get_all_dbvalue()
pm.fill_db() #some problems here, maybe wrong id computation

key = pm.get_id_key('flag')
print(key)


newPMname = [0]*(8*(pm.nb_key_max))
newPMalue = [0]*((1 << 10) * (pm.nb_key_max))

cx = 0
for i in range(len(pm.r1)):
    v3 = pm.r1[i]
    for j in range(8):
        if v3 >> j & 1:
            vname = ParmentierDB.byte2vec(pm.all_dbname[cx])
            for h in range(len(vname)):
                newPMname[64*i + 8*j + h] = vname[h]
            cx += 1
    
pm.dbnameVEC = newPMname
 
cx = 0
for i in range(len(pm.r2)):
    v3 = pm.r2[i]
    for j in range(8):
        if v3 >> j & 1:
            vvalue = ParmentierDB.byte2vec(pm.all_dbvalue[cx])
            for h in range(len(vvalue)):
                newPMalue[1024 * (8 * i + j) + h] = vvalue[h]
            cx += 1
    
pm.dbvalueVEC = newPMalue

value = pm.get_key('flag')
print(''.join(chr(v) for v in value))
```

Cela permet de nous donner le flag finale après quelques heures de debug (problèmes de calcul de l'id, mauvaise DB mémoire à cause d'erreurs) : 

!["Main"](/assets/img/posts/fcsc2024/b5.png "flag")

---
layout: post
title: GCC CTF - BadHabit
subtitle: Analyse de pcap USB
tags: [pcap, hardware, smartcard]
comments: true
---

### GCC CTF - BadHabit

On nous fournit un fichier : usb.pcapng

## Analyse du pcap

un premier coup d'oeil révele que le pcap est un dump USB entre un device extérieur et le pc. 

!["Main"](/assets/img/posts/gcc/usb.png "Wireshark")

Les premiers paquets **GET DESCRIPTOR** permettent de récupérer un IdVendor et un IdProduct du device extérieur : 0x9563 est un smart card reader, on peut trouver cette information dans :

https://github.com/linuxhw/LsUSB

!["Main"](/assets/img/posts/gcc/idproduct.png "IdProduct")

On peut lire également que ce smart card reader utilise EVM.


### Protocole

On a le protocole USB en tout premier pour communiquer avec les devices. 
On peut utiliser le CCID également pour afficher des requêtes USB plus précise : 

!["Main"](/assets/img/posts/gcc/decode.png "Decode as")

Cela nous permet d'afficher des requêtes USB plus précise, on sait également que les smard card reader utilise souvent l'iso 7816 pour communiquer avec l'interface USB. 
On peut mettre donc CCID.payload en iso 7816 sur wireshark.

Ce qui donne : 

!["Main"](/assets/img/posts/gcc/usb2.png "Wireshark")

# Evm

En lisant de plus près le protocole EVM pour les smart card, on doit chercher un SELECT (1PAY.SYS.DDF01)envoyé à la smart card, qui fait office de séléction après la réponse au reset.  
https://www.openscdp.org/scripts/tutorial/emv/applicationselection.html


On le retrouve assez facilement.   
Ne disposant pas d'un tool propre pour parser l'EVM, j'ai dumpé tout les paquets qui était des réponses du smart card vers l'interface, et j'ai retiré tout les octets non EVM (USB/ISO 7816).  
Cela permet de me donner les dumps suivants:

```
7081a857135132630040615951d23022016950876900000f5a0851326300406159515f24032302285f25032002015f280202505f3401018c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d12910a8a0295059f37049f4c089f02069f03068e0a00000000000000001f039f0702ff009f080200039f0d05b4606080009f0e0500100000009f0f05b4606098009f420209
--------------------------------------------------
7081e08f01079f3201039224625c98da7cda5adb0307a26a61f874465b9431766c2c54d3fa706e880b378364a52488039081b0969319618b5a3feb56ef12b80c1f59eba49286670df0a92621954af37f232042a1988d17f56840a1097f497eca80ff609bf2e949910a0c6a3dcec4c6535ee5f5cd1ddadcda1ea5f6b838c1b6b86cb86b692746c3051933cdce2db5abec64e7b00ccbe0312162dd2e0c8012dd48a5fe75c5ec31c96166d654648c89d66d24966511aecf5731f44f480fc1663301dcc23511eec4f2ece6970db925a453a72281a677af21
--------------------------------------------------
70139f47030100019f480a849be16b39620b0317f390
--------------------------------------------------
7081b49f4681b081c136edbb609eab901ebcb662947cab4446ef3e59db7a4009a3d0635e6c898639ba78cecf77ba3a34883156d339cfc85ba6a0d1ec939d6aa86dacec47b8ce5ac98ff2644742aade62e1043576cd331c395ae99e4c9fb4741488e09d5f125b8e5cd218e6abaa9d111d7de6377453d0220bce85a16646dc02c9cc87409e2b2db199fc5f696bd8f1d4e4ba5667d6ba1c8592b3ee5f89ac8161c2fb6cb42fe070c345ea977ac7beee156f46f6fdbab039
--------------------------------------------------
701557135132630040615951d2302201695087690000
--------------------------------------------------
702a9224625c98da7cda5adb0307a26a61f874465b9431766c2c54d3fa706e880b378364a524
--------------------------------------------------
70309f420209789f49039f37049f1f2236393530383736393030303030303036393030303030
--------------------------------------------------
70818f5f25032002015f24032302285a0851326300406159515f3401019f0702ff008e10000000000000000042014403010302039f0d05bc60fc80009f0e0500100000009f0f05bc60fc98005f280202509f4a01828c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d12910a8a029505
--------------------------------------------------
7081bb9081b0969319618b5a3feb56ef12b80c1f59eba49286670df0a92621954af37f232042a1988d17f56840a1097f497eca80ff609bf2e949910a0c6a3dcec4c6535ee5f5cd1ddadcda1ea5f6b838c1b6b86cb86b692746c3051933cdce2db5abec64e7b00ccbe0312162dd2e0c8012dd48a5fe75c5ec31c96166d654648c89d66d24966511aecf5731f44f480fc1663301dcc23511eec4f2ece6970db925a453a72281a677af219abb99a8e0b46a818da08500b0
--------------------------------------------------
7081c79f4681b08110657f1d6d5cb86769ad48418b0e13c2410a168a97e394f6343f27194aa41ccd6f0cee943d3c308f25acab2d85115e874c45ebd51629a6ff4dcd827861fefc2f831198a471bcdc06261c1d714afdcac52bd18326bd27172b0c2fa5c0133caa69006e2f2c087993933cf6086f86fb9db337831445f09759159a46cb868f3e7a2e4c4414ff9a0f2393ebb58fe5ba4bd41d0e4af52724c3864c1452005bc404cee3659cfcd96113e2b94494119c38c77c9f47030100019f480a849be16b3962
```

(on peut utiliser scapy pour parser le pcap)
```python
def extract_packet(pcap_file):
    usb_traffic = []
    packets = rdpcap(pcap_file)
    for pkt in packets:
        raw_packet = raw(pkt)
        rz = len(raw_packet)
        if rz < 41 or rz == 42:
            continue
        usb_traffic.append(raw_packet)

    return usb_traffic
```

# Résolution

Je vais utiliser https://emvlab.org/tlvutils/?data= qui est un excellent site permettant de parser les octets EVM.

Je teste différents dump (plusieurs informations, dont le nom mastercard ressort, ...)

Je finit par tomber sur le dump suivant : 

https://emvlab.org/tlvutils/?data=7081a857135132630040615951d23022016950876900000f5a0851326300406159515f24032302285f25032002015f280202505f3401018c279f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34039f21039f7c148d12910a8a0295059f37049f4c089f02069f03068e0a00000000000000001f039f0702ff009f080200039f0d05b4606080009f0e0500100000009f0f05b4606098009f420209

Cela permet de dumper les 2 informations nécéssaires au challenge : 

!["Main"](/assets/img/posts/gcc/sol.png "EVMLab")

On peut donc récupérer le numéro de la mastercard : 5132630040615951 ainsi que sa date d'expiration : 02/23

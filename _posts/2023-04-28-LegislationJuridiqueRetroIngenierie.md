---
layout: post
title: Legislation Juridique Autour de la rétro-Ingénierie et la publication de recherche.
subtitle: Analyse de différents cas et présentation de loi européenne et française.
tags: [reverse, juridique]
comments: true
---

### Disclaimer

Cet article vise à fournir des informations et un aperçu personnelle sur les lois européennes et françaises relatives à la rétro-ingénierie en matière de cybersécurité. Cependant, il est important de noter que les lois et les réglementations évoluent rapidement et peuvent varier en fonction des juridictions. Cet article ne doit pas être considéré comme un avis juridique et ne peut pas être utilisé comme référence en matière de conformité juridique. Il est fortement recommandé de consulter un professionnel du droit pour obtenir des conseils juridiques spécifiques à votre entreprise ou à votre situation.
De plus cet article reflête d'une analyse personelle et donc possiblement erroné.

### Comprendre les lois européennes et françaises sur la rétro-ingénierie en cybersécurité

La rétro-ingénierie est une technique largement utilisée en cybersécurité pour évaluer la sécurité des logiciels et des systèmes. Cependant, cette pratique peut être soumise à des restrictions légales en raison de la protection des droits de propriété intellectuelle et de la confidentialité des données. Pourtant, certaines exceptions ont été introduites dans les lois européennes et françaises pour permettre la rétro-ingénierie à des fins de recherche en matière de sécurité informatique ou pour garantir l'interopérabilité d'un programme. Dans cet article, je propose d'explorer les lois applicables en Europe et en France en matière de rétro-ingénierie, les conditions à respecter pour l'utiliser dans le cadre de la cybersécurité.


### LES LOIS UTILES

En Europe et en France, la rétro-ingénierie est généralement considérée comme une violation du droit d'auteur et des droits de propriété intellectuelle. Cependant, il existe des exceptions limitées permettant la rétro-ingénierie à des fins spécifiques, telles que la recherche et l'interopérabilité.

En France, l'**article L122-6-1** du Code de la propriété intellectuelle énonce une exception pour la rétro-ingénierie de logiciels afin de permettre l'interopérabilité avec d'autres logiciels. Toutefois, cette exception est soumise à plusieurs conditions strictes (que nous détaillerons dans les exemples).

En Europe, l'**article 6 et 6bis** de la Directive sur le droit d'auteur permet également la rétro-ingénierie à des fins d'interopérabilité, sous certaines conditions similaires.

En ce qui concerne la recherche en matière de sécurité informatique, la **Convention de Budapest sur la cybercriminalité** prévoit des exceptions pour la rétro-ingénierie de logiciels à des fins de recherche en matière de sécurité informatique sous certaines conditions.

### CAS 1 : Logiciel propriétaire

En Europe, la Directive européenne sur le droit d'auteur (**Directive 2009/24/CE**) prévoit une exception pour la rétro-ingénierie à des fins de garantie de l'interopérabilité d'un programme. Cette exception peut être utilisée pour évaluer la sécurité d'un logiciel afin de s'assurer qu'il ne comporte pas de vulnérabilités susceptibles de compromettre les données de l'entreprise.

En France, la loi pour **la confiance dans l'économie numérique (LCEN)** prévoit également une exception pour la rétro-ingénierie de logiciels à des fins d'interopérabilité (**Article 45 A de la LCEN**). Cette exception peut être utilisée pour évaluer la sécurité d'un logiciel à des fins de garantie de l'interopérabilité, sous réserve de respecter les conditions énoncées dans l'article 6 de la Directive européenne sur le droit d'auteur.

De plus, la Convention de Budapest sur la cybercriminalité autorise la rétro-ingénierie de logiciels à des fins de recherche en matière de sécurité informatique, sous certaines conditions strictes.
Ces conditions sont :

- La rétro-ingénierie doit être effectuée à des fins de recherche en matière de sécurité informatique.
- La rétro-ingénierie ne doit être effectuée que par des personnes légitimes, telles que des experts en sécurité informatique ou des organismes de certification. 
- La rétro-ingénierie ne doit être effectuée que sur des systèmes ou des logiciels appartenant au chercheur ou avec le consentement du titulaire des droits. (Ce point est très important)
- Les résultats de la rétro-ingénierie ne peuvent être utilisés que dans le cadre de la recherche en matière de sécurité informatique et ne peuvent pas être utilisés à des fins illégales.

En conclusion, pour un logiciel propriétaire, vous pouvez faire de la rétro-ingénierie à condition de remplir ces conditions.
Attention, certaines juridictions ou des contrats de license peuvent avoir des conditions supplémentaires à respecter pour permettre la rétro-ingénierie à des fins de recherche en matière de sécurité informatique. 

### CAS 2 : Logiciel Open Source

La rétro-ingénierie d'un logiciel open source peut être effectuée plus facilement que pour un logiciel propriétaire. En effet, les licences de logiciel open source telles que la GNU GPL / Apache 2.0 / ... autorisent généralement les utilisateurs à modifier et à distribuer le code source du logiciel.

Cependant, il est important de noter que certaines licences de logiciel open source peuvent comporter des restrictions en matière de rétro-ingénierie. Par exemple, la licence Apache 2.0 autorise la rétro-ingénierie à des fins de débogage, mais interdit la modification du code source et la distribution de toute version modifiée sans l'autorisation des titulaires de droits.

Autrement dit, il n'y a aucun problème pour faire de la rétro-ingénierie à des fins de recherche mais toujours faire attention à la license.

### DIFFUSION DES RECHERCHES

Ce point est toujours difficile. Un chercheur dans une entreprise souhaite publier ses recherches sur le logiciel propriétaire interne de l'entreprise, fourni par un prestataire externe.

Je vais essayer de montrer comment procéder pour les 2 cas : propriétaire et open source pour la diffusion des recherches. 

Contexte : vous êtes un chercheur en entreprise ou un particulier qui découvre une vulnérabilité dans un logiciel propriétaire dont vous possèder la license.
Dans ce contexte, le chercheur doit se conformer à la loi française sur la protection des secret d'affaires. La divulgation des secrets d'affaires est interdite et peut être sanctionnée pénalement. 

En France, il existe en effet une loi qui permet à un chercheur, sous certaines conditions, de publier la vulnérabilité après avoir notifié le prestataire concerné. Il s'agit de la loi **République numérique de 2016**, qui a introduit l'article **L2323-1-2** dans le Code de la défense.

Cet article prévoit que les personnes qui découvrent une vulnérabilité dans un système d'information peuvent la notifier à l'opérateur du système concerné. Si l'opérateur ne répond pas dans un délai de trois mois, ou s'il répond mais ne prend pas les mesures nécessaires pour remédier à la vulnérabilité, la personne concernée peut alors la divulguer publiquement.

IMPORTANT, cette disposition légale ne s'applique pas aux **opérateurs d'importance vitale ou aux opérateurs de service essentiel**, qui sont régis par les dispositions de l'article L151-1 du Code de la sécurité intérieure. Il est donc important de vérifier le statut de l'opérateur concerné avant de publier une vulnérabilité.

En outre il est possible de pouvoir diffuser des recherches sur une vulnérabilité trouvé, même si l'entreprise contacté refuse. 
Cependant, il faut faire très attention au contrat de license du logiciel. 

Pour les logiciels open source, les conditions de divulgation peuvent varier en fonction de la licence sous laquelle le logiciel est publié.

Cependant, même avec un logiciel open source avec des diffusions de recherches plus faciles, il est important de respecter les délais légaux de divulgation ainsi que la notification de la vulnérabilité (peut varier en fonction des licenses mais en général 6mois), surtout si la vulnérabilité pourrait avoir un impact sur la sécurité ou la confidentialité des utilisateurs. 

Pour finir je rapelle que si vous êtes dans un contexte avec potentiellement ders problèmes juridiques ou un litige avec une entreprise, vous devez absolument contacter l'équipe juridique de votre entreprise ou un avocat pour un avis et s'assurer en cas de poursuite par l'entreprise externe. 
Pour avoir connu une situation de ce genre, je sais qu'il peux être très frustant de travailler 6mois sur un projet et ne rien pouvoir publier car l'entreprise qui a crée le logiciel refuse tout publication ou reconaissance de vulnérabilité. Il faut savoir prendre le mal en patience et malheuresement des fois oublier l'idée de pouvoir publier. 

Merci de la lecture ! 
# PNS_IoT_Security_SI5
JavaCard security project made with Arnaud Dumanois, Quentin Maurois and Simon Beurel

# Description

Ce projet consiste à développer un système de terminal et de carte à puce pour créer un porte-monnaie électronique 
sécurisé destiné à des distributeurs automatiques

Voici les principaux aspects sécurisés :

1. Vérification des transactions par un serveur de confiance (back-end) pour :
   - Protéger contre le vol de carte.
   - Éviter l'utilisation de cartes frauduleuses comme des "YesCards" (faux clones).
2. Sécurisation contre des distributeurs automatiques malveillants (faisant semblant d’être légitimes).
3. Compatibilité avec différents types de distributeurs automatiques.

## Fonctionnement attendu

Le terminal enverra des informations sur la transaction (exemple : description des biens achetés) à la carte.     
La carte à puce pourra générer une paire de clés RSA (une clé privée et une clé publique).
- Clé privée : utilisée par la carte pour signer les transactions.
- Clé publique : partagée avec le serveur pour vérifier la validité des signatures.

Les transactions signées seront enregistrées dans un serveur back-end, servant de journal sécurisé des achats.

## Fonctionnalités à l'installation

1. Lors de l'installation, la carte doit être **configurée avec un code PIN** choisit par l'utilisateur. Ce PIN servira à 
protéger la carte contre l'utilisation en cas de vol.

2. La carte doit générer une **paire de clés RSA (clé privée et clé publique)**. La clé publique de la carte sera enregistrée 
sur un serveur de vérification simulant une banque. Ce serveur permettra de vérifier la validité des transactions et de 
protéger contre les cartes volées ou falsifiées.

3. Le serveur doit posséder une paire de clé RSA. La **clé publique du serveur sera enregistrée sur la carte** pour permettre
la sécurisation des transactions.

## Fonctionnalités à l'utilisation

- Signature et chiffrement des données d'achat par la carte, elle aura donc un role de TEE
- Transmission de l'adresse IP du serveur de vérification, la carte doit donc être capable d'envoyer l'IP du serveur
de vérification au distributeur automatique. On doit décider si l'IP doit étre signée ou non pour son authenticité.
- Enregistrement des transactions sur le serveur de vérification, le serveur devra conserver un journal des transactions
mais la carte ne stockera pas ces logs. La liste d'achat ne pourra etre consultée que lorsque la carte est insérée dans 
un lecteur car seule la carte possède la clé privée pour déchiffrer les données.

# Applet JavaCard

## Commandes APDU

Un APDU (Application Protocol Data Unit) est un message échangé entre le terminal et la carte à puce, il s'agit d'une
unité de communication. Les commandes APDU sont utilisées pour envoyer des instructions à la carte et pour recevoir des
réponses de la carte.

### Structure d'une commande APDU et d'une réponse APDU

Une commande APDU est composée de 6 champs :

- CLA (Class) : classe de l'instruction
- INS (Instruction) : instruction
- P1 (Parameter 1) : paramètre 1
- P2 (Parameter 2) : paramètre 2
- Lc (Length of data field) : longueur des données
- Data : données
- Le (Length of expected data) : longueur des données attendues

Une réponse APDU est composée de 2 champs :

- Data : données
- SW1 SW2 (Status Word) : code de statut

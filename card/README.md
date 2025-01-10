# Card

Le code pin par défaut est 1234

# Fonctionnalités

La carte recoit les messages a encrypté et signé (ou a decrypté et vérifié) via un systeme de multi-APDU, une fois recu,
la carte reconstruit le message et effectue l'opération demandée.

On peut également changer le code pin de la carte.

La carte génère une paire de clé RSA 512 bits lors de son initialisation et stocke la clé public du serveur lorsqu'un 
utilisateur entre le code pin.

# Installation

Nous avons developpé sous Windows, pour ce faire nous avant utilisé Ant afin de compiler le projet. Pour ce faire :

- Télécharger  [Java SE Development Kit 8u381](https://www.oracle.com/fr/java/technologies/javase/javase8u211-later-archive-downloads.html) 
- Installer Java dans le dossier spécifié dans ./Common.Properties #JAVA_BUILD_HOME

Pour ce rendu nous vous fournissons les différentes librairie utilisé directement dans le dossier racine du projet. Mais
si vous souhaitez les télécharger vous pouvez le faire via les liens suivants : [GPShell](https://kaoh.github.io/globalplatform/)

- Pour compiler le projet, configurer votre projet Intellij avec le chemin vers le Java 1.8 installé précédemment, et le
language level : SDK default 
- Ensuite ajouter le Ant Build dans Intellij puis dans le menu Ant cliquez sur Binarize.all.standard puis sur build 

Si tout c'est bien passé, vous devriez avoir un dossier out dans le dossier racine du projet contenant les fichiers .cap

# Utilisation

Pour Installer sur la carte, il suffit de lancer dans votre terminal ```gpshell.exe upload.gp```.

Si tout c'est bien passé, la dernière ligne de l'output devrait être : `release_contextcommand time: 0 m`

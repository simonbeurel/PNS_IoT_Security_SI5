from smartcard.System import readers
from smartcard.util import toHexString

# 1. Liste des lecteurs de carte disponibles
r = readers()
if len(r) == 0:
    print("Aucun lecteur de carte trouvé.")
    exit()

# Sélectionner le premier lecteur de carte
reader = r[0]
print(f"Utilisation du lecteur : {reader}")

# 2. Connexion à la carte
connection = reader.createConnection()
connection.connect()

# 3. Envoi de la commande APDU pour l'applet (par exemple 00 40 00 00 00)
apdu = [0x00, 0x40, 0x00, 0x00, 0x00]  # CLA, INS, P1, P2, Lc (longueur des données)

# 4. Envoyer la commande APDU à la carte
response, sw1, sw2 = connection.transmit(apdu)

# 5. Afficher la réponse
print(f"Réponse APDU : {toHexString(response)}")
print(f"SW1 SW2 : {hex(sw1)} {hex(sw2)}")

# SW1 SW2 == 0x9000 signifie succès
if sw1 == 0x90 and sw2 == 0x00:
    print("Succès !")
else:
    print("Erreur lors de la communication avec la carte.")

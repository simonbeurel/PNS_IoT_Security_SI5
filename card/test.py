from smartcard.System import readers
from smartcard.util import toHexString, toBytes

def connect_card():
    r = readers()
    if len(r) == 0:
        print("Aucun lecteur de carte détecté.")
        return None
    connection = r[0].createConnection()
    print("Connexion au lecteur:", r[0])
    connection.connect()
    return connection

def send_apdu(connection, apdu):
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Envoyé: {toHexString(apdu)}")
    print(f"Reçu: {toHexString(response)} {hex(sw1)[2:].zfill(2)} {hex(sw2)[2:].zfill(2)}")
    return response, sw1, sw2

def main():
    connection = connect_card()
    if not connection:
        return

    # Sélectionner l'AID de l'applet installé
    aid = toBytes("a0404142434445461001")  # AID sans l'instance
    select_apdu = [0x00, 0xA4, 0x04, 0x00] + [len(aid)] + aid
    response, sw1, sw2 = send_apdu(connection, select_apdu)

    if sw1 == 0x90 and sw2 == 0x00:
        print("Applet sélectionné avec succès.")

        # Envoyer la commande pour obtenir le message "Hello"
        hello_apdu = [0x80, 0x40, 0x00, 0x00, 0x0c] # 0x0c est la longueur du message
        response, sw1, sw2 = send_apdu(connection, hello_apdu)

        if sw1 == 0x90 and sw2 == 0x00:
            print("Message reçu:", bytes(response).decode('ascii'))
        else:
            print("Erreur lors de la récupération du message.")
    else:
        print("Erreur lors de la sélection de l'applet.")

    connection.disconnect()

if __name__ == "__main__":
    main()

'''
Ce fichier peut etre utilisé pour tester manuellement les fonctionnalité du projet
'''
from reader import SmartCardReader


# Client file

def main():
    """Initialise la connexion avec la carte"""
    reader = SmartCardReader()
    card = reader.get_card_connection()

    print("Card connected and applet selected")
    card.test()
    card.login("1234")

    card.get_server_ip()
    card.exchange_keys_with_server()
    card.verify_server_key()

    """Envoie des différents produits à la carte"""
    card.send_fragmented_message("Barre Proteiné")
    card.process_server_logs()

    return 0

if __name__ == '__main__':
    main()




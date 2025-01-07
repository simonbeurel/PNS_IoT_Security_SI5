from smartcard.System import readers
from smartcard.util import toHexString, toBytes

from card_configuration import INS_LOGIN
from reader import SmartCardReader

def main():
    reader = SmartCardReader()
    card = reader.get_card_connection()

    print("Card connected and applet selected")
    card.test()
    card.login("1234")

    card.get_server_ip()
    card.exchange_keys_with_server()
    card.verify_server_key()

    card.send_fragmented_message("Barre Proteiné")
    card.send_fragmented_message("Canette Coca-Cola")
    card.send_fragmented_message("Paquet de chips")
    card.send_fragmented_message("Madeleine Bretonne")
    card.send_fragmented_message("aaaaaaaaaaaaaaaaaaaaaaaaeefzdsdsqa")
    card.send_fragmented_message("aaaaaaaaaaaaaaaaaaaaaaaaeefzdsdsqa")
    card.process_server_logs()
    return 0

if __name__ == '__main__':
    main()




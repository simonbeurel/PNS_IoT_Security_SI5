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

    # e,n = card.get_public_key()

    card.get_server_ip()
    e, n = card.get_public_key()
    card.send_public_key_to_server(e, n)
    return 0

if __name__ == '__main__':
    main()




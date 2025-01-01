from smartcard.System import readers
from smartcard.util import toHexString, toBytes

from reader import SmartCardReader

def main():
    reader = SmartCardReader()
    card = reader.get_card_connection()

    print("Card connected and applet selected")
    card.test()
    card.login("0000")
    card.modify_pin("1234")
    card.login("1234")
    return 0

if __name__ == '__main__':
    main()




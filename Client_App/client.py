from smartcard.System import readers
from smartcard.util import toHexString, toBytes

from Client_App.reader import SmartCardReader

def main():
    reader = SmartCardReader()
    card = reader.get_card_connection()

    print("Card connected")
    print("Test command")
    card.test()
    return 0






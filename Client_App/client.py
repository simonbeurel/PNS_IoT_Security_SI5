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

    e,n = card.get_public_key()

    '''
    pin_code = [0x31, 0x32, 0x33, 0x34]
    login_apdu = [0x00, INS_LOGIN, 0x00, 0x00, 0x04] + pin_code
    print(toHexString(login_apdu))
    response, sw1, sw2 = card.connection.transmit(login_apdu)
    print(f"sw1: {sw1:02X}, sw2: {sw2:02X}")
    '''
    return 0

if __name__ == '__main__':
    main()




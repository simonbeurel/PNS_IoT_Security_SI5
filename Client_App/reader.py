from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from smartcard.util import toHexString

from commands import CardCommands
from apdu import APDU
from commands import CardCommands
from card_configuration import *

def is_success(sw1, sw2):
    if (sw1, sw2) == (0x90, 0x00):
        return True

class SmartCardReader:
    def __init__(self):
        self.reader = None
        self.connection = None
        self.card = None

    def get_card_connection(self) -> CardCommands:
        if not readers():
            print("No readers")
            return None

        for reader in readers():
            try:
                connection = reader.createConnection()
                connection.connect()
                if not connection:
                    return

                card = CardCommands(connection)
                print("Selecting applet")
                print(APPLET_AID)
                response, sw1, sw2 = card.send_command(apdu_select_applet(APPLET_AID))


                print(f"sw1: {sw1:02X}, sw2: {sw2:02X}")
                if is_success(sw1, sw2):
                    self.reader = reader
                    self.connection = connection
                    self.card = card
                    return card

            except NoCardException:
                print("No card in reader")
                return None

def apdu_select_applet(applet_aid):
    apdu = APDU(0x00, 0xa4, 0x04, 0x00, applet_aid)
    print(toHexString(apdu.get_apdu()))
    return apdu
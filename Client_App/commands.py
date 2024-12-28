from apdu import APDUHandler
from card_configuration import *

class CardCommands:

    def __init__(self, connection):
        self.connection = connection
        self.apdu_handler = APDUHandler(connection)

    def send_command(self, command):
        return self.apdu_handler.send_command(command)

    def test(self):
        apdu = APDU(APPLET_CLA, INS_TEST, 0, 0)
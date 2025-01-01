from smartcard.util import toHexString

from apdu import APDUHandler, APDU
from card_configuration import *

class CardCommands:

    def __init__(self, connection):
        self.connection = connection
        self.apdu_handler = APDUHandler(connection)

    def send_command(self, command):
        return self.apdu_handler.send_command(command)

    def test(self):
        apdu = APDU(APPLET_CLA, INS_TEST, 0, 0)
        print(apdu)
        response, sw1, sw2 = self.send_command(apdu)
        if is_success(sw1, sw2):
            print("Test success")
            print(bytes(response))
        else:
            print("Test failed")
        return response

    def login(self, pin_code):
        if len(pin_code) != PIN_SIZE:
            print("Le code pin doit faire 4 chiffre")
            return

        data = [int(digit) for digit in pin_code]
        apdu = APDU(APPLET_CLA, INS_LOGIN,0,0, data)
        response, sw1, sw2 = self.send_command(apdu)
        print(f"sw1: {sw1:02X}, sw2: {sw2:02X}")
        if is_success(sw1,sw2):
            print("Connexion réussie")
        else:
            print("Connexion échoué")
        return response

    def modify_pin(self, new_pin):
        if len(new_pin) != PIN_SIZE:
            print("Le code pin doit faire 4 chiffre")
            return

        data = [int(digit) for digit in new_pin]
        apdu = APDU(APPLET_CLA, INS_MODIFY_PIN, 0, 0, data)

        response, sw1, sw2 = self.send_command(apdu)
        print(f"sw1: {sw1:02X}, sw2: {sw2:02X}")
        if is_success(sw1, sw2):
            print("Modification réussie")
        else:
            print("Modification échoué")

        return response

    def get_public_key(self):
        apdu = APDU(APPLET_CLA, INS_SEND_PUBLIC_KEY, 0, 0)
        response, sw1, sw2 = self.send_command(apdu)
        print(f"sw1: {sw1:02X}, sw2: {sw2:02X}")
        if is_success(sw1, sw2):
            print("Récupération de la clé publique réussie")
            e, n = deserialize_e_n(response)
            print(f"e: {e}")
            print(f"n: {n}")
            return e, n
        else:
            print("Récupération de la clé publique échouée")


def is_success(sw1, sw2):
    success = (sw1 == 0x90 and sw2 == 0x00)

    if not success:
        import inspect
        import os
        file_path = inspect.stack()[1].filename
        file_name = os.path.basename(file_path)
        caller = inspect.stack()[1].function
        line_no = inspect.stack()[1].lineno
        print(f"Error from file {file_name} in function \"{caller}\" at line {line_no}")
    return success

def deserialize_e_n(data):
    len_e = int.from_bytes(data[:2], "big")
    e = int.from_bytes(data[2:2 + len_e], "big")
    len_n = int.from_bytes(data[2 + len_e:2 + len_e + 2], "big")
    n = int.from_bytes(data[2 + len_e + 2:2 + len_e + 2 + len_n], "big")
    return e, n
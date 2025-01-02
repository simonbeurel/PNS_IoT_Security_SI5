import json
import socket
from typing import Tuple


from apdu import APDUHandler, APDU
from card_configuration import *

class CardCommands:

    def __init__(self, connection):
        self.connection = connection
        self.apdu_handler = APDUHandler(connection)
        self.trusted_server = None
        self.port = 12345

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
            public_key = (e, n)
            self.send_public_key_to_server(public_key)
            return e, n
        else:
            print("Récupération de la clé publique échouée")

    def get_server_ip(self):
        apdu = APDU(APPLET_CLA, INS_GET_SERVER_IP, 0, 0)
        response, sw1, sw2 = self.send_command(apdu)
        print(f"sw1: {sw1:02X}, sw2: {sw2:02X}")
        if is_success(sw1, sw2):
            print("Récupération de l'adresse IP et du port du serveur réussie")
            ip = ".".join([str(byte) for byte in response[:4]])
            port = int.from_bytes(response[4:], "big")
            self.trusted_server = ip
            self.port = port
            print(f"Adresse IP du serveur: {ip}")
            print(f"Port du serveur: {port}")
        else:
            print("Récupération de l'adresse IP du serveur échouée")

    def send_public_key_to_server(self, public_key: Tuple[int, int]):
        """Envoie la clé publique au serveur"""
        try:
            e, n = public_key
            key_data = {
                'type': 'store_key',
                'client_id': 'card_' + str(id(self)),  # Identifiant unique pour la carte
                'public_key': {
                    'n': n,
                    'e': e
                }
            }

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.trusted_server, self.port))
                s.send(json.dumps(key_data).encode())

                response = s.recv(1024)
                response_data = json.loads(response.decode())

                if response_data['status'] == 'success':
                    print("Clé publique envoyée et stockée avec succès")
                else:
                    print("Erreur lors de l'envoi de la clé publique")

        except Exception as e:
            print(f"Erreur lors de l'envoi de la clé publique: {e}")



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

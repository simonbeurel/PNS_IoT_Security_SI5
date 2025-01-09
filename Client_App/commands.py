import base64
import json
import socket
from io import BytesIO
from typing import Tuple

import rsa

from apdu import APDUHandler, APDU
from card_configuration import *

class CardCommands:

    def __init__(self, connection):
        self.connection = connection
        self.apdu_handler = APDUHandler(connection)
        self.trusted_server = None
        self.port = 12345
        self.server_public_key = None
        self.card_public_key = None

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
        if is_success(sw1,sw2):
            return True
        else:
            return False

    def modify_pin(self, new_pin):
        if len(new_pin) != PIN_SIZE:
            print("Le code pin doit faire 4 chiffre")
            return

        data = [int(digit) for digit in new_pin]
        apdu = APDU(APPLET_CLA, INS_MODIFY_PIN, 0, 0, data)

        response, sw1, sw2 = self.send_command(apdu)
        if is_success(sw1, sw2):
            print("Modification réussie")
        else:
            print("Modification échoué")

        return response

    def get_public_key(self):
        apdu = APDU(APPLET_CLA, INS_SEND_PUBLIC_KEY, 0, 0)
        response, sw1, sw2 = self.send_command(apdu)
        if is_success(sw1, sw2):
            print("Récupération de la clé publique réussie")
            e, n = deserialize_e_n(response)
            return e, n
        else:
            print("Récupération de la clé publique échouée")

    def get_server_ip(self):
        apdu = APDU(APPLET_CLA, INS_GET_SERVER_IP, 0, 0)
        response, sw1, sw2 = self.send_command(apdu)
        if is_success(sw1, sw2):
            print("Récupération de l'adresse IP et du port du serveur réussie")
            ip = ".".join([str(byte) for byte in response[:4]])
            port = int.from_bytes(response[4:], "big")
            self.trusted_server = ip
            self.port = port
        else:
            print("Récupération de l'adresse IP du serveur échouée")

    def exchange_keys_with_server(self):
        """Effectue l'échange de clés avec le serveur"""
        try:
            # 1. Obtenir d'abord notre clé publique de la JavaCard
            public_key = self.get_public_key()
            if not public_key:
                return False

            e, n = public_key
            self.card_public_key = rsa.PublicKey(n=n, e=e)

            # 2. Préparer le message d'échange de clés
            key_data = {
                'type': 'key_exchange',
                'client_id': 'card_' + str(id(self)),
                'public_key': {
                    'n': n,
                    'e': e
                }
            }

            # 3. Établir la connexion et envoyer notre clé
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.trusted_server, self.port))
                s.send(json.dumps(key_data).encode())

                # 4. Recevoir la clé du serveur
                response = s.recv(1024)
                response_data = json.loads(response.decode())

                if response_data['status'] == 'success':
                    # 5. Stocker la clé du serveur
                    server_key = response_data['public_key']
                    self.server_public_key = rsa.PublicKey(n=server_key['n'], e=server_key['e'])

                    # 6. Envoyer la clé du serveur à la JavaCard
                    success = self.store_server_key(server_key['e'], server_key['n'])
                    if success:
                        print("Échange complet des clés réussi")
                        return True
                    else:
                        print("Échec lors du stockage de la clé serveur sur la JavaCard")
                        return False
                else:
                    print("Erreur lors de l'échange de clés")
                    return False

        except Exception as e:
            print(f"Erreur lors de l'échange de clés: {e}")
            return False

    def store_server_key(self, e, n):
        """Stocke la clé publique du serveur sur la JavaCard"""
        # Convertir e et n en bytes
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

        # Préparer les données à envoyer
        data = [
            len(e_bytes),  # Longueur de e
            *e_bytes,  # e
            len(n_bytes),  # Longueur de n
            *n_bytes  # n
        ]

        # Envoyer l'APDU pour stocker la clé
        apdu = APDU(APPLET_CLA, INS_STORE_SERVER_KEY, 0, 0, data)
        response, sw1, sw2 = self.send_command(apdu)
        if is_success(sw1, sw2):
            return True
        else:
            return False

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

    def verify_server_key(self):
        """Vérifie que la clé du serveur est correctement stockée sur la JavaCard"""
        apdu = APDU(APPLET_CLA, INS_VERIFY_SERVER_KEY, 0, 0)
        response, sw1, sw2 = self.send_command(apdu)
        if is_success(sw1, sw2):
            e, n = deserialize_e_n(response)
            # Vérifier que la clé correspond à celle du serveur
            if self.server_public_key:
                if e == self.server_public_key.e and n == self.server_public_key.n:
                    print("La clé correspond à celle du serveur")
                else:
                    print("La clé ne correspond pas à celle du serveur")
            return e, n
        else:
            print("Vérification de la clé serveur échouée")
            return None

    def check_card_signature(self, encrypted_data, signature):
        """Vérifie la signature de la carte"""
        try:
            # Convertir les données en un objet file-like
            message = BytesIO(bytes(encrypted_data))
            signature = bytes(signature)

            # Vérifier la signature avec la clé publique de la carte
            rsa.verify(message, signature, self.card_public_key)
            return True
        except rsa.VerificationError:
            print("Échec de la vérification de la signature")
            return False
        except Exception as e:
            print(f"Erreur lors de la vérification de la signature : {e}")
            return False

    def send_transaction_to_server(self, encrypted_data, signature):
        try:
            encrypted_b64 = base64.b64encode(bytes(encrypted_data)).decode()
            signature_b64 = base64.b64encode(bytes(signature)).decode()
            # Préparer les données de transaction
            transaction_data = {
                'type': 'transaction',
                'client_id': 'card_' + str(id(self)),
                'encrypted_data': encrypted_b64,
                'signature': signature_b64
            }

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.trusted_server, self.port))
                s.send(json.dumps(transaction_data).encode())

                response = s.recv(1024)
                response_data = json.loads(response.decode())

                if response_data['status'] == 'success':
                    print("Transaction envoyée avec succès")
                    return True
                else:
                    print("Erreur lors de l'envoi de la transaction")
                    return False
        except Exception as e:
            print(f"Erreur lors de l'envoi de la transaction: {e}")
            return False

    def send_fragmented_message(self, message: str):
        """
        Sends a message to the card in fragments, gets back encrypted and signed response
        """
        message_bytes = message.encode(TEXT_ENCODING)
        chunk_size = 12  # Maximum size for each fragment

        # Send first fragment
        data = [c for c in message_bytes[:chunk_size]]
        apdu = APDU(APPLET_CLA, INS_FRAGMENT, 0x00, 0x00, data)  # P1=START, P2=RECEIVE
        response, sw1, sw2 = self.send_command(apdu)
        if not is_success(sw1, sw2):
            print("Failed to send first fragment")
            return None

        pos = chunk_size
        while pos < len(message_bytes) - chunk_size:
            data = [c for c in message_bytes[pos:pos + chunk_size]]
            apdu = APDU(APPLET_CLA, INS_FRAGMENT, 0x01, 0x00, data)  # P1=CONTINUE
            response, sw1, sw2 = self.send_command(apdu)
            if not is_success(sw1, sw2):
                print(f"Failed to send fragment at position {pos}")
                return None

            pos += chunk_size

        if pos < len(message_bytes):
            data = [c for c in message_bytes[pos:]]
            apdu = APDU(APPLET_CLA, INS_FRAGMENT, 0x02, 0x00, data)  # P1=FINAL
            response, sw1, sw2 = self.send_command(apdu)
            if not is_success(sw1, sw2):
                print("Failed to send final fragment")
                return None

        complete_response = []

        while True:
            apdu = APDU(APPLET_CLA, INS_FRAGMENT, 0x00, 0x01)  # P2=SEND
            response, sw1, sw2 = self.send_command(apdu)

            if not is_success(sw1, sw2):
                print("Failed to receive response fragment")
                return None

            complete_response.extend(response)

            if len(response) < 128:
                break

        encrypted_length = int.from_bytes(complete_response[:2], 'big')
        encrypted_data = complete_response[2:2 + encrypted_length]
        signature = complete_response[2 + encrypted_length:]

        if not self.check_card_signature(encrypted_data, signature):
            print("Failed to verify card signature")
            return None

        success = self.send_transaction_to_server(encrypted_data, signature)
        return success

    def secure_transaction_fragmented(self, transaction_data: str):
        """
        Process a secure transaction using fragmented messages
        """
        if not self.card_public_key or not self.server_public_key:
            print("Keys not initialized. Please exchange keys first.")
            return False

        return self.send_fragmented_message(transaction_data)

    def get_logs_from_server(self):
        """Récupère les logs du serveur pour cette carte"""
        try:
            if not self.trusted_server or not self.port:
                print("Configuration serveur manquante. Exécutez get_server_ip() d'abord.")
                return None

            # Préparer la requête
            request = {
                'type': 'get_logs',
                'client_id': 'card_' + str(id(self))
            }

            # Envoyer la requête au serveur
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.trusted_server, self.port))
                s.send(json.dumps(request).encode())

                # Recevoir la réponse
                response = s.recv(4096)  # Buffer plus grand pour les logs
                response_data = json.loads(response.decode())

                if response_data['status'] == 'success':
                    for log in response_data['logs']:
                        log['encrypted_data'] = base64.b64decode(log['encrypted_data'])
                        log['signature'] = base64.b64decode(log['signature'])
                    return response_data['logs']
                else:
                    print(f"Erreur serveur: {response_data.get('message', 'Erreur inconnue')}")
                    return None

        except Exception as e:
            print(f"Erreur lors de la récupération des logs: {e}")
            return None

    def process_server_logs(self):
        """Récupère et traite les logs du serveur"""
        # Récupérer les logs du serveur
        logs = self.get_logs_from_server()
        if not logs:
            print("Aucun log à traiter")
            return []

        decrypted_messages = []
        for log_entry in logs:
            try:
                encrypted_data = log_entry['encrypted_data']
                chunk_size = 12

                # Premier fragment
                data = [b for b in encrypted_data[:chunk_size]]
                apdu = APDU(APPLET_CLA, INS_DECRYPT, 0x00, 0x00, data)  # P1=START, P2=RECEIVE
                response, sw1, sw2 = self.send_command(apdu)
                if not is_success(sw1, sw2):
                    print(f"Échec de l'envoi du premier fragment pour le message du {log_entry['timestamp']}")
                    continue

                # Fragments du milieu
                pos = chunk_size
                while pos < len(encrypted_data) - chunk_size:
                    data = [b for b in encrypted_data[pos:pos + chunk_size]]
                    apdu = APDU(APPLET_CLA, INS_DECRYPT, 0x01, 0x00, data)  # P1=CONTINUE
                    response, sw1, sw2 = self.send_command(apdu)
                    if not is_success(sw1, sw2):
                        print(f"Échec de l'envoi d'un fragment pour le message du {log_entry['timestamp']}")
                        break
                    pos += chunk_size

                # Dernier fragment
                if pos < len(encrypted_data):
                    data = [b for b in encrypted_data[pos:]]
                    apdu = APDU(APPLET_CLA, INS_DECRYPT, 0x02, 0x00, data)  # P1=FINAL
                    response, sw1, sw2 = self.send_command(apdu)

                    if not is_success(sw1, sw2):
                        print(f"Échec de l'envoi du dernier fragment pour le message du {log_entry['timestamp']}")
                        continue

                # Récupérer le message déchiffré
                decrypted_data = []
                while True:
                    apdu = APDU(APPLET_CLA, INS_DECRYPT, 0x00, 0x01)  # P2=SEND
                    response, sw1, sw2 = self.send_command(apdu)

                    if not is_success(sw1, sw2):
                        print(f"Échec de la réception du message déchiffré du {log_entry['timestamp']}")
                        break

                    decrypted_data.extend(response)
                    if len(response) < 128:  # Dernier fragment
                        break

                if decrypted_data:
                    try:
                        message = bytes(decrypted_data).decode(TEXT_ENCODING)
                        decrypted_messages.append({
                            'timestamp': log_entry['timestamp'],
                            'message': message,
                            'signature_verified': log_entry['signature_verified']
                        })
                    except UnicodeDecodeError:
                        print(f"Erreur de décodage du message du {log_entry['timestamp']}")

            except Exception as e:
                print(f"Erreur lors du traitement du log du {log_entry['timestamp']}: {e}")
                continue
        return decrypted_messages


def is_success(sw1, sw2):
    success = (sw1 == 0x90 and sw2 == 0x00)
    return success

def deserialize_e_n(data):
    len_e = int.from_bytes(data[:2], "big")
    e = int.from_bytes(data[2:2 + len_e], "big")
    len_n = int.from_bytes(data[2 + len_e:2 + len_e + 2], "big")
    n = int.from_bytes(data[2 + len_e + 2:2 + len_e + 2 + len_n], "big")
    return e, n

'''
    def secure_transaction(self, transaction_data):
        """
        Chiffre et signe les données de transaction en une seule opération
        """
        transaction_data_encoded = transaction_data.encode(TEXT_ENCODING)
        data = [c for c in transaction_data_encoded]

        apdu = APDU(APPLET_CLA, INS_ENCRYPT_AND_SIGN, 0, 0, data)
        response, sw1, sw2 = self.send_command(apdu)

        if not is_success(sw1, sw2):
            print("Échec de la transaction sécurisée")
            return None

        # Extraire les différentes parties de la réponse
        encrypted_length = int.from_bytes(response[:2], 'big')
        encrypted_data = response[2:2 + encrypted_length]
        signature = response[2 + encrypted_length:]

        print(f"encrypted_data: {encrypted_data}")
        print(f"signature: {signature}")

        # Verifier la signature de la carte
        if not self.check_card_signature(encrypted_data, signature):
            print("Échec de la vérification de la signature de la carte")
            return False

        print("Signature de la carte vérifiée avec succès")
        success = self.send_transaction_to_server(encrypted_data, signature)
        return success
'''
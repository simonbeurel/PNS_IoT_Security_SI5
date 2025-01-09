import base64
import json
import signal
import socket
import sys
from pathlib import Path

import rsa
from rsa.cli import encrypt

from Trusted_Server.KeyManager import RSAKeyManager
from Trusted_Server.TransactionLogger import TransactionLogger


class RSAServer:
    def __init__(self, host="localhost", port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key = None
        self.private_key = None
        self.key_manager = RSAKeyManager()
        self.transaction_logger = TransactionLogger()

        self.generate_rsa_keys()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def generate_rsa_keys(self):
        """Génère une paire de clés RSA."""
        (self.public_key, self.private_key) = rsa.newkeys(512)
        print("Clés RSA générées.")

    def store_client_public_key(self, client_id: str, public_key_data: dict):
        """Stocker la clé publique du client"""
        try:
            public_key = self.key_manager.deserialize_public_key(public_key_data)
            self.key_manager.save_public_key(client_id, public_key)
            return True
        except Exception as e:
            print(f"Erreur lors du stockage de la clé publique: {e}")
            return False

    def handle_transaction(self, message):
        try:
            client_id = message['client_id']
            # Convertir les données de base64 en bytes si nécessaire
            encrypted_data = base64.b64decode(message['encrypted_data']) if isinstance(message['encrypted_data'],
                                                                                       str) else message[
                'encrypted_data']
            signature = base64.b64decode(message['signature']) if isinstance(message['signature'], str) else message[
                'signature']
            # 1. Vérifier la signature avec la clé publique du client
            client_public_key = self.key_manager.get_public_key(client_id)
            if not client_public_key:
                raise Exception("Clé client non trouvée")

            verification_status = False
            try:
                # Vérifier la signature des données chiffrées
                rsa.verify(encrypted_data, signature, client_public_key)
                verification_status = True
                print(f"Signature vérifiée avec succès pour le client {client_id}")

                # 2. Déchiffrer les données avec notre clé privée
                decrypted_data = rsa.decrypt(encrypted_data, self.private_key)
                print(f"Données déchiffrées: {decrypted_data.decode('utf-8')}")

                # 3. Stocker la transaction
                self.transaction_logger.log_transaction(
                    client_id,
                    encrypted_data,
                    signature,
                    verification_status
                )

                return {
                    'status': 'success',
                    'message': 'Transaction vérifiée et enregistrée'
                }

            except rsa.VerificationError:
                print(f"Échec de la vérification de signature pour le client {client_id}")
                # On log quand même la transaction mais avec verification_status = False
                self.transaction_logger.log_transaction(
                    client_id,
                    encrypted_data,
                    signature,
                    verification_status
                )
                return {
                    'status': 'error',
                    'message': 'Signature invalide'
                }

        except Exception as e:
            print(f"Erreur lors du traitement de la transaction: {e}")
            return {
                'status': 'error',
                'message': f'Erreur de traitement: {str(e)}'
            }

    def handle_client(self, client_socket):
        """Gérer la communication avec le client"""
        try:
            data = client_socket.recv(1024)
            if not data:
                return

            message = json.loads(data.decode())
            if message['type'] == 'transaction':
                response = self.handle_transaction(message)
                client_socket.send(json.dumps(response).encode())

            if message['type'] == 'key_exchange':
                # 1. Stocker la clé du client
                success = self.store_client_public_key(
                    message['client_id'],
                    message['public_key']
                )

                # 2. Préparer la réponse avec notre clé publique
                response = {
                    'status': 'success' if success else 'error',
                    'message': 'Échange de clés réussi' if success else 'Erreur lors de l\'échange',
                    'public_key': {
                        'n': self.public_key.n,
                        'e': self.public_key.e
                    }
                }

                print(f"Clé client stockée: {success}")
                print(f"Envoi de notre clé publique...")
                client_socket.send(json.dumps(response).encode())

            if message['type'] == 'get_logs':
                client_id = message['client_id']
                logs = self.transaction_logger.get_logs_for_client(client_id)
                card_public_key = self.key_manager.get_public_key(client_id)
                print(f"logs {logs}")
                for log in logs:
                    rsa.verify(base64.b64decode(log['encrypted_data']), base64.b64decode(log['signature']), card_public_key)
                    decrypted_data = rsa.decrypt(base64.b64decode(log['encrypted_data']), self.private_key)
                    signature = base64.b64decode(log['signature'].encode('utf-8'))

                    encrypted_data = rsa.encrypt(decrypted_data, card_public_key)

                    log['encrypted_data'] = base64.b64encode(encrypted_data).decode('utf-8')  # Encodage en base64
                    log['signature'] = base64.b64encode(signature).decode('utf-8')  # Encodage en base64
                response = {
                    'status': 'success',
                    'logs': logs
                }
                client_socket.send(json.dumps(response).encode())

        except Exception as e:
            print(f"Erreur lors du traitement du client: {e}")
            # Envoyer une réponse d'erreur au client
            error_response = {
                'status': 'error',
                'message': f'Erreur serveur: {str(e)}'
            }
            try:
                client_socket.send(json.dumps(error_response).encode())
            except:
                pass
        finally:
            client_socket.close()

    def start(self):
        """Démarrer le serveur pour écouter les connexions"""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)
            print(f"Serveur en écoute sur {self.host}:{self.port}...")

            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connexion reçue de {client_address}")
                self.handle_client(client_socket)
        except KeyboardInterrupt:
            self.cleanup()
        except Exception as e:
            print(f"Erreur dans le serveur: {e}")
            self.cleanup()

        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connexion reçue de {client_address}")
            self.handle_client(client_socket)

    def cleanup(self):
        """Nettoie les ressources du serveur"""
        try:
            # Ferme le socket
            self.server_socket.close()
            # Nettoie les clés
            self.key_manager.cleanup()
            print("Serveur arrêté proprement")
        except Exception as e:
            print(f"Erreur lors de l'arrêt du serveur: {e}")

    def signal_handler(self, signum, frame):
        """Gestionnaire des signaux d'arrêt"""
        print("\nArrêt du serveur...")
        self.cleanup()
        sys.exit(0)

# Fonction pour tester le serveur
if __name__ == "__main__":
    server = RSAServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nArrêt manuel du serveur...")

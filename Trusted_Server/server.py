import json
import signal
import socket
import sys

import rsa

from Trusted_Server.KeyManager import RSAKeyManager


class RSAServer:
    def __init__(self, host="localhost", port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key = None
        self.private_key = None
        self.key_manager = RSAKeyManager()
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

    def handle_client(self, client_socket):
        """Gérer la communication avec le client"""
        try:
            data = client_socket.recv(1024)
            if not data:
                return

            message = json.loads(data.decode())
            print(f"Message reçu: {message}")

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

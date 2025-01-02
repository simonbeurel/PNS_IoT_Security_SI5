import socket
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class VerificationServer:
    def __init__(self):
        # Générer la paire de clés RSA du serveur
        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=512,
        )
        self.server_public_key = self.server_private_key.public_key()

        # Dictionnaire pour stocker les clés publiques des cartes
        self.card_public_keys = {}
        self.ip = ""

    def register_card(self, card_id, card_public_key_pem):
        """Enregistrer la clé publique d'une carte"""
        card_public_key = serialization.load_pem_public_key(card_public_key_pem)
        self.card_public_keys[card_id] = card_public_key
        print(f"Clé publique de la carte {card_id} enregistrée.")

    def verify_signature(self, card_id, message, signature):
        """Vérifier la signature d'un message avec la clé publique de la carte"""
        card_public_key = self.card_public_keys.get(card_id)
        if card_public_key is None:
            print(f"Aucune clé publique trouvée pour la carte {card_id}.")
            return False

        try:
            # Vérifier la signature avec la clé publique de la carte
            card_public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print(f"Signature vérifiée avec succès pour la carte {card_id}.")
            return True
        except Exception as e:
            print(f"Échec de la vérification de la signature pour la carte {card_id}: {e}")
            return False

    def process_message(self, message):
        """Traiter un message signé et chiffré"""
        try:
            # Décoder le message JSON
            data = json.loads(message)

            card_id = data.get("card_id")
            signed_message = bytes.fromhex(data.get("signed_message"))
            encrypted_message = bytes.fromhex(data.get("encrypted_message"))

            # Vérifier la signature du message
            if not self.verify_signature(card_id, encrypted_message, signed_message):
                return "Signature invalide."

            # Simuler la décryption du message (ici, juste afficher)
            print(f"Message déchiffré : {encrypted_message.decode()}")

            return "Message traité avec succès."

        except Exception as e:
            return f"Erreur lors du traitement du message : {e}"

    def run(self, host="127.0.0.1", port=12345):
        """Lancer le serveur"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Serveur de vérification en écoute sur {host}:{port}...")
        self.ip = socket.gethostbyname(socket.gethostname())
        print(f"Adresse IP du serveur : {self.ip}")
        while True:
            # Attendre la connexion d'un client
            client_socket, client_address = server_socket.accept()
            print(f"Connexion reçue de {client_address}")

            try:
                # Recevoir les données du client
                data = client_socket.recv(1024).decode()

                if data:
                    print(f"Message reçu : {data}")
                    response = self.process_message(data)
                    client_socket.sendall(response.encode())
            except Exception as e:
                print(f"Erreur de communication : {e}")
            finally:
                client_socket.close()

# Fonction principale pour démarrer le serveur
if __name__ == "__main__":
    server = VerificationServer()
    server.run()

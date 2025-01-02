import socket
import rsa

class RSAServer:
    def __init__(self, host="localhost", port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.public_key = None
        self.private_key = None
        self.client_public_key = None
        self.generate_rsa_keys()

    def generate_rsa_keys(self):
        """Génère une paire de clés RSA."""
        (self.public_key, self.private_key) = rsa.newkeys(512)
        print("Clés RSA générées.")

    def get_server_ip(self):
        """Obtenir l'IP du serveur."""
        return socket.gethostbyname(socket.gethostname())

    def store_client_public_key(self, public_key_data):
        """Stocker la clé publique du client."""
        try:
            # Charger directement les données en tant que bytes
            self.client_public_key = rsa.PublicKey.load_pkcs1(public_key_data, format="DER")
            print("Clé publique du client stockée.")
            print(f"client_public_key: {self.client_public_key}")
        except Exception as e:
            print(f"Impossible de stocker la clé publique du client: {e}")

    def handle_client(self, client_socket):
        """Gérer la communication avec le client."""
        try:
            # Lecture de la taille des données (4 octets en big-endian)
            data_size = int.from_bytes(client_socket.recv(4), "big")
            data = client_socket.recv(data_size)

            command = data.decode("utf-8", errors="ignore").split(" ", 1)
            if command[0] == "GET_IP":
                server_ip = self.get_server_ip()
                client_socket.sendall(len(server_ip).to_bytes(4, "big") + server_ip.encode())
            elif command[0] == "GET_PUBLIC_KEY":
                public_key_der = self.public_key.save_pkcs1(format="DER")
                client_socket.sendall(len(public_key_der).to_bytes(4, "big") + public_key_der)
            elif command[0] == "SET_PUBLIC_KEY":
                public_key_der = command[1].encode()  # Attend un format DER
                self.store_client_public_key(public_key_der)
                response = "Cle publique client stockee."
                client_socket.sendall(len(response).to_bytes(4, "big") + response.encode())
            else:
                response = "Commande inconnue."
                client_socket.sendall(len(response).to_bytes(4, "big") + response.encode())
        except Exception as e:
            print(f"Erreur lors du traitement du client : {e}")
            client_socket.sendall(len("Erreur interne.").to_bytes(4, "big") + b"Erreur interne.")
        finally:
            client_socket.close()

    def start(self):
        """Démarrer le serveur pour écouter les connexions."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        print(f"Serveur en écoute sur {self.host}:{self.port}...")

        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"Connexion reçue de {client_address}")
            self.handle_client(client_socket)

# Lancer le serveur
if __name__ == "__main__":
    server = RSAServer()
    server.start()

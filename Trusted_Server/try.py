import socket
import json

def test_server():
    server_host = "localhost"  # Ou l'IP du serveur, par ex : "192.168.1.100"
    server_port = 12345

    # Créer une connexion au serveur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_host, server_port))

        # Exemple de message signé et chiffré
        test_message = {
            "card_id": "card123",
            "signed_message": "746573745f7369676e6564",  # Valeur en hex (exemple)
            "encrypted_message": "746573745f6d657373616765"  # Valeur en hex (exemple)
        }

        # Envoyer le message au serveur
        client_socket.sendall(json.dumps(test_message).encode())

        # Recevoir la réponse du serveur
        response = client_socket.recv(1024).decode()
        print(f"Réponse du serveur : {response}")

if __name__ == "__main__":
    test_server()

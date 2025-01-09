import shutil
from datetime import datetime

import rsa
import json
import base64
from pathlib import Path
from typing import Dict


class RSAKeyManager:
    def __init__(self, keys_directory: str = "keys"):
        self.keys_directory = Path(keys_directory)
        self.keys_directory.mkdir(exist_ok=True)
        self.keys_cache: Dict[str, rsa.PublicKey] = {}


    def serialize_public_key(self, public_key: rsa.PublicKey) -> dict:
        """Sérialise une clé publique RSA en format JSON-compatible"""
        return {
            'n': public_key.n,
            'e': public_key.e
        }

    def deserialize_public_key(self, key_data: dict) -> rsa.PublicKey:
        """Désérialise une clé publique RSA depuis un format JSON"""
        return rsa.PublicKey(n=key_data['n'], e=key_data['e'])

    def save_public_key(self, client_id: str, public_key: rsa.PublicKey):
        """Sauvegarde une clé publique dans un fichier JSON"""
        key_data = self.serialize_public_key(public_key)
        key_file = self.keys_directory / f"{client_id}_public.json"

        with open(key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
        print(f"Clé publique pour {client_id} sauvegardée avec succès")
        self.keys_cache[client_id] = public_key

    def load_public_key(self, client_id: str) -> rsa.PublicKey:
        """Charge une clé publique depuis un fichier JSON"""
        if client_id in self.keys_cache:
            return self.keys_cache[client_id]

        key_file = self.keys_directory / f"{client_id}_public.json"
        if not key_file.exists():
            raise FileNotFoundError(f"No public key found for client {client_id}")

        with open(key_file, 'r') as f:
            key_data = json.load(f)

        public_key = self.deserialize_public_key(key_data)
        self.keys_cache[client_id] = public_key
        return public_key

    def store_transaction(self, client_id: str, encrypted_data: bytes, signature: bytes) -> bool:
        """Stocke une transaction dans le fichier texte"""
        try:
            # On encode les données binaires en base64 pour le stockage texte
            enc_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            sig_b64 = base64.b64encode(signature).decode('utf-8')
            timestamp = datetime.now().isoformat()

            transaction = {
                'client_id': client_id,
                'encrypted_data': enc_b64,
                'signature': sig_b64,
                'timestamp': timestamp
            }

            # Écriture dans le fichier (une transaction par ligne)
            with open(self.transaction_file, 'a') as f:
                f.write(json.dumps(transaction) + '\n')
            return True

        except Exception as e:
            print(f"Erreur lors du stockage de la transaction: {e}")
            return False



    def verify_signature(self, client_id: str, data: bytes, signature: bytes) -> bool:
        """Vérifie la signature des données"""
        try:
            public_key = self.load_public_key(client_id)
            rsa.verify(data, signature, public_key)
            return True
        except Exception as e:
            print(f"Erreur de vérification de signature: {e}")
            return False

    def cleanup(self):
        """Nettoie les fichiers"""
        try:
            self.keys_cache.clear()
            if self.keys_directory.exists():
                shutil.rmtree(self.keys_directory)
            if Path(self.transaction_file).exists():
                Path(self.transaction_file).unlink()
        except Exception as e:
            print(f"Erreur lors du nettoyage: {e}")

    def get_public_key(self, client_id):
        """Récupère la clé publique d'un client"""
        try:
            return self.load_public_key(client_id)
        except Exception as e:
            print(f"Erreur lors de la récupération de la clé publique: {e}")
            return None
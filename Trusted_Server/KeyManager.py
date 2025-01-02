import shutil

import rsa
import json
import base64
from pathlib import Path
from typing import Tuple, Dict


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
        # Mise à jour du cache
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

    def cleanup(self):
        """Nettoie le cache des clés"""
        try:
            # Vide le cache
            self.keys_cache.clear()

            # Supprime le répertoire des clés et son contenu
            if self.keys_directory.exists():
                shutil.rmtree(self.keys_directory)
                print("Nettoyage des clés effectué avec succès")
        except Exception as e:
            print(f"Erreur lors du nettoyage des clés: {e}")
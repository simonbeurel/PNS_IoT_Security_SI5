import base64
import json
from datetime import datetime


class TransactionLogger:
    def __init__(self, filename="transaction_log.txt"):
        self.filename = filename

    def log_transaction(self, client_id: str, encrypted_data: bytes, signature: bytes, verification_status: bool):
        """Log une transaction dans le fichier texte"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Convertir les données binaires en base64 pour le stockage texte
            encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            signature_b64 = base64.b64encode(signature).decode('utf-8')

            log_entry = {
                "timestamp": timestamp,
                "client_id": client_id,
                "encrypted_data": encrypted_b64,
                "signature": signature_b64,
                "signature_verified": verification_status
            }

            with open(self.filename, "a") as f:
                f.write(json.dumps(log_entry) + "\n")

        except Exception as e:
            print(f"Erreur lors de la journalisation de la transaction: {e}")
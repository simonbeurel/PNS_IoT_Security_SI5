from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import os
from card_configuration import INS_LOGIN
from reader import SmartCardReader


class VendingMachine:
    def __init__(self):
        self.reader = SmartCardReader()
        self.card = self.reader.get_card_connection()
        self.authenticated = False
        self.products = {
            '1': {'name': 'Barre Protéinée', 'price': 2.50},
            '2': {'name': 'Canette Coca-Cola', 'price': 1.50},
            '3': {'name': 'Paquet de chips', 'price': 1.80},
            '4': {'name': 'Madeleine Bretonne', 'price': 1.20},
            '5': {'name': 'Eau minérale', 'price': 1.00},
        }
        self.cart = []

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_menu(self):
        self.clear_screen()
        print("=== Machine Distributrice ===")
        if not self.authenticated:
            print("1. Se connecter (PIN requis)")
            print("0. Quitter")
        else:
            print("1. Voir les produits")
            print("2. Voir le panier")
            print("3. Payer")
            print("4. Changer le code PIN")
            print("5. Voir l'historique des achats")
            print("0. Se déconnecter")

    def display_products(self):
        self.clear_screen()
        print("=== Produits disponibles ===")
        for id, product in self.products.items():
            print(f"{id}. {product['name']} - {product['price']}€")
        print("\n0. Retour au menu")

    def calculate_total(self):
        return sum(product['price'] for product in self.cart)

    def display_cart(self):
        self.clear_screen()
        print("=== Votre panier ===")
        if not self.cart:
            print("Le panier est vide")
        else:
            for product in self.cart:
                print(f"{product['name']} - {product['price']}€")
            print(f"\nTotal: {self.calculate_total():.2f}€")
        input("\nAppuyez sur Entrée pour continuer...")

    def login(self):
        while True:
            pin = input("Entrez votre code PIN (4 chiffres): ")
            if len(pin) != 4 or not pin.isdigit():
                print("Le PIN doit contenir exactement 4 chiffres.")
                continue

            try:
                print("\nAuthentification...")
                response = self.card.login(pin)
                if response == False:
                    print("Code PIN incorrect!")
                    input("Appuyez sur Entrée pour continuer...")
                    return
                print("Authentification réussie!")
                print("\nInitialisation de la connexion sécurisée...")
                self.card.get_server_ip()
                self.card.exchange_keys_with_server()
                self.card.verify_server_key()
                self.authenticated = True
                return
            except Exception as e:
                print(f"Erreur lors de la connexion: {e}")
                return

    def add_to_cart(self):
        while True:
            self.display_products()
            choice = input("\nChoisissez un produit (0 pour terminer): ")

            if choice == '0':
                break

            if choice in self.products:
                self.cart.append(self.products[choice])
                print(f"\n{self.products[choice]['name']} ajouté au panier!")
                input("Appuyez sur Entrée pour continuer...")
            else:
                print("\nProduit invalide!")
                input("Appuyez sur Entrée pour continuer...")

    def format_transaction_message(self):
        """Formate le message de transaction avec tous les produits et le total"""
        products_list = " + ".join([product['name'] for product in self.cart])
        total = self.calculate_total()
        return f"{products_list} : {total:.2f}€"

    def process_payment(self):
        if not self.cart:
            print("Le panier est vide!")
            input("Appuyez sur Entrée pour continuer...")
            return

        print("\nTraitement du paiement...")
        try:
            # Envoie une seule transaction avec tous les produits
            transaction_message = self.format_transaction_message()
            self.card.send_fragmented_message(transaction_message)

            print("Paiement effectué avec succès!")
            self.cart = []  # Vider le panier après le paiement
            input("Appuyez sur Entrée pour continuer...")
        except Exception as e:
            print(f"Erreur lors du paiement: {e}")
            input("Appuyez sur Entrée pour continuer...")

    def change_pin(self):
        while True:
            new_pin = input("Entrez le nouveau code PIN (4 chiffres): ")
            if len(new_pin) != 4 or not new_pin.isdigit():
                print("Le PIN doit contenir exactement 4 chiffres.")
                continue

            try:
                self.card.modify_pin(new_pin)
                input("Appuyez sur Entrée pour continuer...")
                break
            except Exception as e:
                print(f"Erreur lors du changement de PIN: {e}")
                input("Appuyez sur Entrée pour continuer...")
                break

    def view_purchase_history(self):
        print("\nRécupération de l'historique des achats...")
        try:
            logs = self.card.process_server_logs()
            if logs:
                print("\n=== Historique des achats ===")
                for log in logs:
                    print(f"Date: {log['timestamp']}")
                    print(f"Transaction: {log['message']}")
                    print(f"Signature vérifiée: {'Oui' if log['signature_verified'] else 'Non'}")
                    print("-" * 40)
            else:
                print("Aucun historique d'achat disponible.")
            input("\nAppuyez sur Entrée pour continuer...")
        except Exception as e:
            print(f"Erreur lors de la récupération de l'historique: {e}")
            input("Appuyez sur Entrée pour continuer...")

    def run(self):
        while True:
            self.display_menu()
            choice = input("\nChoisissez une option: ")

            if not self.authenticated:
                if choice == '1':
                    self.login()
                elif choice == '0':
                    print("Au revoir!")
                    break
                else:
                    print("Option invalide!")
                    input("Appuyez sur Entrée pour continuer...")
            else:
                if choice == '1':
                    self.add_to_cart()
                elif choice == '2':
                    self.display_cart()
                elif choice == '3':
                    self.process_payment()
                elif choice == '4':
                    self.change_pin()
                elif choice == '5':
                    self.view_purchase_history()
                elif choice == '0':
                    self.authenticated = False
                    self.cart = []
                    print("Déconnexion réussie!")
                    input("Appuyez sur Entrée pour continuer...")
                else:
                    print("Option invalide!")
                    input("Appuyez sur Entrée pour continuer...")


def main():
    vending_machine = VendingMachine()
    vending_machine.run()


if __name__ == '__main__':
    main()
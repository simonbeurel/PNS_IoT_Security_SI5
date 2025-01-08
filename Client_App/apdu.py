import math
from dataclasses import dataclass
from typing import List, Optional

from smartcard.util import toHexString

from card_configuration import *


class APDU:
    def __init__(self, cla, ins, p1, p2, data=None, receive_length=0):
        """
        Initialise une commande APDU avec les champs suivants :
        - cla : Classe d'instruction 
        - ins : Instruction 
        - p1, p2 : Paramètres associés à l'instruction
        - data : Données à envoyer avec la commande 
        - receive_length : Longueur attendue de la réponse, si aucune donnée n'est envoyée
        """
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2

        if data is int:
            self.data = [data]
        if data and not all(isinstance(byte, int)  for byte in data):
            raise ValueError("les données doivent être une liste d'entiers")

        # Si des données sont fournies, calcule leur longueur (Lc)
        if data:
            self.data = data
            self.lc = len(data)
        else:
            self.receive_length = receive_length

    def get_apdu(self):
        """
        Retourne la commande APDU sous forme de liste d'octets, incluant :
        - Les 4 octets de la commande (CLA, INS, P1, P2)
        - Lc et les données, ou la longueur attendue de la réponse (Le)
        """
        if hasattr(self, 'data'):
            return [self.cla, self.ins, self.p1, self.p2, self.lc] + self.data
        else:
            return [self.cla, self.ins, self.p1, self.p2, self.receive_length]


    def __str__(self):
        return self.get_apdu().__str__()

class APDUHandler:
    def __init__(self, connection):
        """
        Initialise le gestionnaire avec une connexion.
        """
        self.connection = connection

    def send_command(self, apdu: APDU):
        response, sw1, sw2 = self.connection.transmit(apdu.get_apdu())
        if sw1 == SW1_RETRY_WITH_LE:
            apdu = APDU(apdu.cla, apdu.ins, apdu.p1, apdu.p2, receive_length=sw2)
            return self.send_command(apdu)
        if sw1 == SW1_RETRY_WITH_GET_RESPONSE_61 or sw1 == SW1_RETRY_WITH_GET_RESPONSE_9F:
            apdu = APDU(apdu.cla, INS_GET_RESPONSE, apdu.p1, apdu.p2, receive_length=sw2)
            return self.send_command(apdu)
        return response, sw1, sw2
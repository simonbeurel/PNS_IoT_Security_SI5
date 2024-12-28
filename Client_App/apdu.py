from smartcard.util import toHexString

from Client_App.card_configuration import SW1_RETRY_WITH_LE, INS_GET_RESPONSE


class APDU:
    def __init__(self, cla, ins, p1, p2, data=None, receive_length=0):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data if data else []

        if data is int:
            self.data = [data]
        if data and not all(isinstance(byte, int) for byte in data):
            raise ValueError("les données doivent être une liste d'entiers")

        if data:
            self.data = data
            self.lc = len(data)
        else:
            self.receive_length = receive_length

    def get_apdu(self):
        if hasattr(self, 'data'):
            return [self.cla, self.ins, self.p1, self.p2, self.lc] + self.data
        else:
            return [self.cla, self.ins, self.p1, self.p2, self.receive_length]


    def __str__(self):
        data_str = " ".join(f"{byte:02X}" for byte in self.data)
        return f"APDU(CLA={self.cla:02X}, INS={self.ins:02X}, P1={self.p1:02X}, P2={self.p2:02X}, Data=[{data_str}])"


class APDUHandler:
    def __init__(self, connection):
        self.connection = connection

    def send_command(self, apdu: APDU):
        response, sw1, sw2 = self.connection.transmit(apdu.get_apdu())

        if sw1 == SW1_RETRY_WITH_LE:
            # on envoit l'APDU avec le bon LE
            apdu = APDU(apdu.cla, apdu.ins, apdu.p1, apdu.p2, receive_length=sw2)
            return self.send_command(apdu)
        if sw1 == SW1_RETRY_WITH_GET_RESPONSE_61 or sw1 == SW1_RETRY_WITH_GET_RESPONSE_9F:
            # si ca marche pas on envoit un GET RESPONSE pour récupérer le reste des données
            apdu = APDU(apdu.cla, INS_GET_RESPONSE, apdu.p1, apdu.p2, receive_length=sw2)
            return self.send_command(apdu)
        return response, sw1, sw2

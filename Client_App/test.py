from smartcard.System import readers
from smartcard.util import toHexString, toBytes


def send_login_apdu():
    # AID of the applet - you'll need to replace this with your actual AID
    # This is typically defined when installing the applet
    APPLET_AID = toBytes("a0404142434445461001")

    # Constants from the Java code
    CLA = 0x00
    INS_LOGIN = 0x01
    DEFAULT_PIN = [0x00, 0x00, 0x00, 0x00]

    # SELECT APDU
    select_apdu = [0x00, 0xA4, 0x04, 0x00] + [len(APPLET_AID)] + APPLET_AID

    # LOGIN APDU
    login_apdu = [
                     CLA,
                     INS_LOGIN,
                     0x00,
                     0x00,
                     0x04,
                 ] + DEFAULT_PIN

    try:
        r = readers()
        if len(r) < 1:
            print("No readers found")
            return

        print(f"Using reader: {r[0]}")
        connection = r[0].createConnection()
        connection.connect()

        # First select the applet
        print("Sending SELECT APDU:")
        print(f"-> {toHexString(select_apdu)}")
        data, sw1, sw2 = connection.transmit(select_apdu)
        print(f"Select Response: SW1: {hex(sw1)}, SW2: {hex(sw2)}")

        if (sw1, sw2) != (0x90, 0x00):
            print("Failed to select applet")
            return

        # Then send login command
        print("\nSending LOGIN APDU:")
        print(f"-> {toHexString(login_apdu)}")
        data, sw1, sw2 = connection.transmit(login_apdu)
        print(f"Login Response: SW1: {hex(sw1)}, SW2: {hex(sw2)}")

        # Check response
        if (sw1, sw2) == (0x90, 0x00):
            print("Login successful!")
        elif (sw1, sw2) == (0x69, 0x82):
            print("Login failed: Security status not satisfied (wrong PIN)")
        elif (sw1, sw2) == (0x69, 0x85):
            print("Login failed: Conditions not satisfied (already logged in)")
        elif (sw1, sw2) == (0x6D, 0x00):
            print("Instruction not supported - Make sure applet is properly selected")
        else:
            print(f"Unknown response: {hex(sw1)}{hex(sw2)}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    send_login_apdu()
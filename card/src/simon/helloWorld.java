package simon;

import javacard.framework.*;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;


public class helloWorld extends Applet {

    private final static byte[] hello=
            {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x74} ;

    public static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};
    public static final byte PIN_LENGTH = 4;
    public static final byte MAX_PIN_TRIES = 3;

    OwnerPIN pin;
    /*
      On définit les constantes pour les différentes instructions
    */
    private final static byte CLA = (byte) 0x00; // CLA
    private final static byte INS_LOGIN = (byte) 0x01; // Inscription
    private final static byte INS_MODIFY_PIN = (byte) 0x02; // Modification du PIN
    private final static byte INS_TEST = (byte) 0x09; // Test

    protected helloWorld() {
        pin = new OwnerPIN(MAX_PIN_TRIES, PIN_LENGTH);
        pin.update(DEFAULT_PIN, (short) 0, PIN_LENGTH);
        register();
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new helloWorld();
    }


    public void process(APDU apdu) {
        if (selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        }

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // on choisit l'instruction à exécuter en fonction de la valeur de INS
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_TEST:
                test(apdu);
                break;
            case INS_LOGIN:
                login(apdu);
                break;
            case INS_MODIFY_PIN:
                modifyPin(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void test(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(hello, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) hello.length);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) hello.length);
    }

    private void login(APDU apdu) {
        if (pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);


        // Copie les données reçues dans la réponse pour débogage
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, buffer, (short) 0, lc);
        apdu.setOutgoingAndSend((short) 0, lc);
        checkPin(buffer);
    }


    private void checkPin(byte[] buffer) {
        if (buffer[ISO7816.OFFSET_LC] != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH)) {
            ISOException.throwIt((short) (0x69E1));
        }
    }


    private void checkLogin() {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void modifyPin(APDU apdu) {
        checkLogin();
        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_LC] != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH);
    }
}

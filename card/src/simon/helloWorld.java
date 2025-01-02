package simon;

import javacard.framework.*;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;


public class helloWorld extends Applet {

    private final static byte[] hello=
            {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x74} ;

    public static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};
    public static final byte PIN_LENGTH = (byte) 0x04;
    public static final byte MAX_PIN_TRIES = (byte) 0x03;

    private static final byte[] SERVER_IP = {0x7F, 0x00, 0x00, 0x01};
    private static final short SERVER_PORT = 12345;

    private KeyPair keyPair;
    private RSAPublicKey publicKey;
    private RSAPrivateCrtKey privateKey;
    private RSAPublicKey serverPublicKey;

    OwnerPIN pin;
    private final static short SW_VERIFICATION_FAILED = 0x6300;
    /*
      On définit les constantes pour les différentes instructions
    */
    private final static byte CLA = (byte) 0x00; // CLA
    private final static byte INS_LOGIN = (byte) 0x01; // Inscription
    private final static byte INS_MODIFY_PIN = (byte) 0x02; // Modification du PIN
    private final static byte INS_SEND_PUBLIC_KEY = (byte) 0x03; // Envoi de la clé publique
    private final static byte INS_GET_SERVER_IP = (byte) 0x04; // Récupération de l'adresse IP du serveur
    private final static byte INS_GET_SERVER_PUBLIC_KEY = (byte) 0x05; // Récupération de la clé publique du serveur


    private final static byte INS_TEST = (byte) 0x09; // Test

    protected helloWorld() {
        pin = new OwnerPIN(MAX_PIN_TRIES, PIN_LENGTH);
        pin.update(DEFAULT_PIN, (short) 0, PIN_LENGTH);
        generateRSAKeyPair();
        register();
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new helloWorld();
    }

    public boolean select() {
        return pin.getTriesRemaining() != 0;
    }

    public void deselect() {
        checkLogin();
        pin.reset();
    }


    private void generateRSAKeyPair() {
        keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, (short) 512);
        keyPair.genKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
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
            case INS_SEND_PUBLIC_KEY:
                sendPublicKey(apdu);
                break;
            case INS_GET_SERVER_IP:
                Util.arrayCopy(SERVER_IP, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) SERVER_IP.length);
                Util.setShort(buffer, (short) (ISO7816.OFFSET_CDATA + SERVER_IP.length), SERVER_PORT);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (SERVER_IP.length + 2));
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
        byte[] buffer = apdu.getBuffer();
        if((short) (buffer[ISO7816.OFFSET_LC] & 0x00FF)==PIN_LENGTH) {
            apdu.setIncomingAndReceive();
            if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_LENGTH))
                ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
        else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    private void checkLogin() {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void modifyPin(APDU apdu) {
        checkLogin();
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        if (buffer[ISO7816.OFFSET_LC] != PIN_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        pin.update(buffer, ISO7816.OFFSET_CDATA , PIN_LENGTH);
    }

    private short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        // Code from the thread in stackoverflow :
        // https://stackoverflow.com/questions/42690733/javacard-send-rsa-public-key-in-apdu

        short expLen = key.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);
        short modLen = key.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short) (offset + 2 + expLen), modLen);
        return (short) (4 + expLen + modLen);
    }

    private void sendPublicKey(APDU apdu) {
        checkLogin();
        byte[] buffer = apdu.getBuffer();
        short len = serializeKey(publicKey, buffer, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
    }
}

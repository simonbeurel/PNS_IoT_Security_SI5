package simon;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Util;

import java.security.interfaces.RSAPublicKey;


public class helloWorld extends Applet {

    private final static byte[] hello=
            {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x74} ;

    private final static byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};
    private final static byte PIN_SIZE = 4;
    private final static byte MAX_PIN_TRIES = 3;

    private OwnerPIN pin;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private KeyPair keyPair;

    private RSAPublicKey serverPublicKey;

    private final static short RSA_KEY_SIZE = 1024;

    /*
        On définit les constantes pour les différentes instructions
     */
    private final static byte INS_LOGIN = (byte) 0x10; // Inscription
    private final static byte INS_MODIFY_PIN = (byte) 0x20; // Modification du PIN
    private final static byte INS_SIGN = (byte) 0x30;
    private final static byte INS_VERIFY = (byte) 0x40; // Vérification du PIN
    private final static byte INS_SEND_PUBLIC_KEY_TO_SERVER = (byte) 0x50; // Envoi de la clé publique au serveur
    private final static byte INS_PAY = (byte) 0x60; // Paiement
    private final static byte INS_GET_SERVER_IP = (byte) 0x70; // Récupération de l'adresse IP du serveur
    private final static byte INS_DECRYPT_LOGS = (byte) 0x80; // Déchiffrement des logs



    protected helloWorld() {
        pin = new OwnerPIN(MAX_PIN_TRIES, PIN_SIZE);
        pin.update(DEFAULT_PIN, (short) 0, PIN_SIZE);
        generateKeyPair();
        register();
    }


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new helloWorld();
    }

    private void generateKeyPair() {
        keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, RSA_KEY_SIZE);
        keyPair.genKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
    }

    /*
        On sérialise la clé publique pour pouvoir l'envoyer au serveur et la stocker dans la mémoire
     */
    private short serializePublicKey(RSAPublicKey publicKey, byte[] buffer, short offset) {
        // Récupération de l'exposant
        short expLen = publicKey.getExponent(buffer, (short) (offset + 2));
        Util.setShort(buffer, offset, expLen);

        // Récupération du modulus
        short modLen = publicKey.getModulus(buffer, (short) (offset + 4 + expLen));
        Util.setShort(buffer, (short) (offset + 2 + expLen), modLen);

        return (short) (4 + expLen + modLen); // Longueur totale de la clé sérialisée
    }


}








/*
public static void install(byte[] buffer, short offset, byte length)
{
    // GP-compliant JavaCard applet registration
    new helloWorld().register();
}

public void process(APDU apdu) {
    // Good practice: Return 9000 on SELECT
    if (selectingApplet()) {
        return;
    }

    byte[] buf = apdu.getBuffer();
    switch (buf[ISO7816.OFFSET_INS]) {
        case (byte) 0x40:
            Util.arrayCopy(hello, (byte)0, buf, ISO7816.OFFSET_CDATA, (byte)12);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (byte)12);
            break;
        default:
            // good practice: If you don't know the INStruction, say so:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
 */
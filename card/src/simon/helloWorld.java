package simon;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;


public class helloWorld extends Applet {

    private final static byte[] hello=
            {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x6f, 0x62, 0x65, 0x72, 0x74} ;

    public static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};
    public static final byte PIN_LENGTH = (byte) 0x04;
    public static final byte MAX_PIN_TRIES = (byte) 0x03;

    private static final byte[] SERVER_IP = {0x7F, 0x00, 0x00, 0x01};
    private static final short SERVER_PORT = 12345;

    // Add these fields to the JavaCard class
    private static final short MAX_BUFFER_SIZE = 512;
    private byte[] messageBuffer;
    private short messageLength;
    private boolean isReceiving;
    private short currentOffset;


    // Add new instruction
    private static final byte INS_FRAGMENT_DATA = (byte) 0x08;
    private static final byte P1_START = (byte) 0x00;
    private static final byte P1_CONTINUE = (byte) 0x01;
    private static final byte P1_FINAL = (byte) 0x02;
    private static final byte P2_RECEIVE = (byte) 0x00;
    private static final byte P2_SEND = (byte) 0x01;

    private KeyPair keyPair;
    private RSAPublicKey publicKey;
    private RSAPrivateCrtKey privateKey;
    private RSAPublicKey serverPublicKey;

    OwnerPIN pin;
    private final static short SW_VERIFICATION_FAILED = 0x6300;

    //On définit les constantes pour les différentes instructions
    private final static byte CLA = (byte) 0x00; // CLA
    private final static byte INS_LOGIN = (byte) 0x01; // Inscription
    private final static byte INS_MODIFY_PIN = (byte) 0x02; // Modification du PIN
    private final static byte INS_SEND_PUBLIC_KEY = (byte) 0x03; // Envoi de la clé publique
    private final static byte INS_GET_SERVER_IP = (byte) 0x04; // Récupération de l'adresse IP du serveur
    private final static byte INS_STORE_SERVER_KEY = (byte) 0x05; // Récupération et stockage de la clé publique du serveur
    private static final byte INS_VERIFY_SERVER_KEY = (byte) 0x06; // Vérification de la clé publique du serveur
    private static final byte INS_ENCRYPT_AND_SIGN  = (byte) 0x07; // Signature de données
    private static final byte INS_FRAGMENT  = (byte) 0x08;
    private final static byte INS_TEST = (byte) 0x09;
    private final static byte INS_DECRYPT = (byte) 0x0A;

    protected helloWorld() {
        messageBuffer = new byte[MAX_BUFFER_SIZE];
        messageLength = 0;
        isReceiving = false;
        currentOffset = 0;

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
            case INS_STORE_SERVER_KEY:
                storeServerKey(apdu);
                break;
            case INS_VERIFY_SERVER_KEY:
                verifyServerKey(apdu);
                break;
            case INS_ENCRYPT_AND_SIGN :
                encryptAndSign(apdu);
                break;
            case INS_FRAGMENT:
                if (buffer[ISO7816.OFFSET_P2] == P2_RECEIVE) {
                    receiveFragment(apdu, INS_FRAGMENT);
                } else if (buffer[ISO7816.OFFSET_P2] == P2_SEND) {
                    sendFragment(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
                break;
            case INS_DECRYPT:
                if (buffer[ISO7816.OFFSET_P2] == P2_RECEIVE) {
                    receiveFragment(apdu, INS_DECRYPT);
                } else if (buffer[ISO7816.OFFSET_P2] == P2_SEND) {
                    sendFragment(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                }
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

    private void storeServerKey(APDU apdu) {
        checkLogin();
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (buffer[ISO7816.OFFSET_LC] == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        try {
            if (serverPublicKey == null) {
                serverPublicKey = (RSAPublicKey) KeyBuilder.buildKey(
                        KeyBuilder.TYPE_RSA_PUBLIC,
                        KeyBuilder.LENGTH_RSA_512,
                        false);
            }

            // Lire la longueur de l'exposant (e)
            short offset = ISO7816.OFFSET_CDATA;
            short eLength = (short)(buffer[offset] & 0xFF);
            offset++;

            // Vérifier que nous avons assez de données
            if (eLength <= 0 || eLength > 128) { // 128 octets devraient être suffisants pour un exposant RSA
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // Définir l'exposant
            serverPublicKey.setExponent(buffer, offset, eLength);
            offset += eLength;

            // Lire la longueur du modulus (n)
            short nLength = (short)(buffer[offset] & 0xFF);
            offset++;

            // Vérifier que nous avons assez de données
            if (nLength <= 0 || nLength > 64) { // 64 octets pour une clé RSA 512-bit
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }

            // Définir le modulus
            serverPublicKey.setModulus(buffer, offset, nLength);
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private void verifyServerKey(APDU apdu) {
        checkLogin();

        if (serverPublicKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short len = serializeKey(serverPublicKey, buffer, ISO7816.OFFSET_CDATA);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
    }

    private void encryptAndSign(APDU apdu) {
        checkLogin();

        if (serverPublicKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short dataLength = apdu.setIncomingAndReceive();

        // Buffer temporaire pour stocker les données chiffrées
        byte[] tempBuffer = new byte[256];

        // 1. Chiffrer avec la clé publique du serveur
        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipher.init(serverPublicKey, Cipher.MODE_ENCRYPT);
        short encryptedLength = cipher.doFinal(
                buffer, ISO7816.OFFSET_CDATA,
                dataLength,
                tempBuffer, (short)0
        );

        // 2. Signer les données chiffrées
        Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        sig.init(privateKey, Signature.MODE_SIGN);

        // Copier la longueur des données chiffrées (2 bytes)
        Util.setShort(buffer, ISO7816.OFFSET_CDATA, encryptedLength);

        // Copier les données chiffrées
        Util.arrayCopy(tempBuffer, (short)0,
                buffer, (short)(ISO7816.OFFSET_CDATA + 2),
                encryptedLength);

        // Calculer et ajouter la signature des données chiffrées
        short signatureLength = sig.sign(
                buffer, (short)(ISO7816.OFFSET_CDATA + 2),
                encryptedLength,
                buffer, (short)(ISO7816.OFFSET_CDATA + 2 + encryptedLength)
        );

        // Envoyer le tout
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA,
                (short)(2 + encryptedLength + signatureLength));
    }

    public void receiveFragment(APDU apdu, byte ins) {
        checkLogin();

        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];

        // Start of new message
        if (p1 == P1_START) {
            messageLength = 0;
            isReceiving = true;
            currentOffset = 0;
        }

        // Verify we're in receiving state
        if (!isReceiving) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        short len = apdu.setIncomingAndReceive();

        // Check if buffer overflow would occur
        if ((short)(messageLength + len) > MAX_BUFFER_SIZE) {
            isReceiving = false;
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Copy fragment to buffer
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, messageBuffer, messageLength, len);
        messageLength += len;

        // If this is the final fragment, process the complete message
        if (p1 == P1_FINAL) {
            isReceiving = false;
            if (ins == INS_FRAGMENT) {
                processCompleteMessage(apdu);
            } else {
                decryptCompleteMessage();
            }
        }
    }

    private void processCompleteMessage(APDU apdu) {
        // Create temporary buffer for encrypted data and signature
        byte[] tempBuffer = new byte[256];

        // 1. Encrypt the complete message
        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipher.init(serverPublicKey, Cipher.MODE_ENCRYPT);
        short encryptedLength = cipher.doFinal(
                messageBuffer, (short)0,
                messageLength,
                tempBuffer, (short)0
        );

        // 2. Sign the encrypted data
        Signature sig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        sig.init(privateKey, Signature.MODE_SIGN);

        // Store encrypted length at start of buffer
        Util.setShort(messageBuffer, (short)0, encryptedLength);

        // Copy encrypted data after length
        Util.arrayCopy(tempBuffer, (short)0,
                messageBuffer, (short)2,
                encryptedLength);

        // Add signature after encrypted data
        short signatureLength = sig.sign(
                messageBuffer, (short)2,
                encryptedLength,
                messageBuffer, (short)(2 + encryptedLength)
        );

        // Store total message length for sending
        messageLength = (short)(2 + encryptedLength + signatureLength);
        currentOffset = 0;
    }

    public void sendFragment(APDU apdu) {
        checkLogin();

        byte[] buffer = apdu.getBuffer();
        short maxChunkSize = 128; // Maximum size that can fit in APDU

        short remainingBytes = (short)(messageLength - currentOffset);
        short chunkSize = (remainingBytes > maxChunkSize) ? maxChunkSize : remainingBytes;

        Util.arrayCopy(messageBuffer, currentOffset,
                buffer, ISO7816.OFFSET_CDATA,
                chunkSize);

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, chunkSize);
        currentOffset += chunkSize;

        // If all data has been sent, reset buffer
        if (currentOffset >= messageLength) {
            messageLength = 0;
            currentOffset = 0;
        }
    }

    private void decryptCompleteMessage() {
        try {
            // Créer un buffer temporaire pour le déchiffrement
            byte[] tempBuffer = new byte[256];

            // Déchiffrer avec notre clé privée
            Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
            cipher.init(privateKey, Cipher.MODE_DECRYPT);

            // Le message reçu contient les données chiffrées
            short decryptedLength = cipher.doFinal(
                    messageBuffer, (short)0,
                    messageLength,
                    tempBuffer, (short)0
            );

            // Copier le résultat déchiffré dans le buffer de message
            Util.arrayCopy(tempBuffer, (short)0,
                    messageBuffer, (short)0,
                    decryptedLength);

            messageLength = decryptedLength;
            currentOffset = 0;

        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
}

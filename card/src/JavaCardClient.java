import javax.smartcardio.*;
import java.util.List;

public class JavaCardClient {

    private static final byte CLA = (byte) 0x00;
    private static final byte INS_TEST = (byte) 0x09;
    private static final byte INS_LOGIN = (byte) 0x01;
    private static final byte[] APPLET_AID = {(byte) 0xA0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x10, 0x01};
    private static final byte[] DEFAULT_PIN = {0x01, 0x02, 0x03, 0x04};

    public static void main(String[] args) {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();

            if (terminals.isEmpty()) {
                System.out.println("No card terminals found.");
                return;
            }

            CardTerminal terminal = terminals.get(0);
            System.out.println("Using terminal: " + terminal.getName());

            if (!terminal.isCardPresent()) {
                System.out.println("No card present in the terminal.");
                return;
            }

            Card card = terminal.connect("T=0");
            System.out.println("Card connected: " + card);

            CardChannel channel = card.getBasicChannel();

            // Select Applet APDU Command
            byte[] selectCommand = new byte[5 + APPLET_AID.length];
            selectCommand[0] = (byte) 0x00; // CLA
            selectCommand[1] = (byte) 0xA4; // INS (SELECT)
            selectCommand[2] = 0x04; // P1
            selectCommand[3] = 0x00; // P2
            selectCommand[4] = (byte) APPLET_AID.length; // Lc
            System.arraycopy(APPLET_AID, 0, selectCommand, 5, APPLET_AID.length);

            ResponseAPDU selectResponse = channel.transmit(new CommandAPDU(selectCommand));
            System.out.println("Select Applet Response: " + bytesToHex(selectResponse.getBytes()));

            // Test APDU Command
            byte[] testCommand = {CLA, INS_TEST, 0x00, 0x00, 0x00};
            ResponseAPDU testResponse = channel.transmit(new CommandAPDU(testCommand));
            System.out.println("Test Response: " + displayResponse(testResponse));

            // Login APDU Command
            byte[] loginCommand = new byte[5 + DEFAULT_PIN.length];
            loginCommand[0] = CLA; // CLA
            loginCommand[1] = INS_LOGIN; // INS
            loginCommand[2] = 0x00; // P1
            loginCommand[3] = 0x00; // P2
            loginCommand[4] = (byte) DEFAULT_PIN.length; // Lc
            System.arraycopy(DEFAULT_PIN, 0, loginCommand, 5, DEFAULT_PIN.length);
            System.out.println("Login APDU Command: " + bytesToHex(loginCommand));

            ResponseAPDU loginResponse = channel.transmit(new CommandAPDU(loginCommand));
            System.out.println("Login Response: " + displayResponse(loginResponse));



            card.disconnect(false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    private static String hexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    private static String bytesToString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append((char) b);
        }
        return sb.toString();
    }

    private static String displayResponse(ResponseAPDU response) {
        return "SW1: " + Integer.toHexString(response.getSW1()) + ", SW2: " + Integer.toHexString(response.getSW2()) + ", Data: " + bytesToString(response.getData());
    }
}

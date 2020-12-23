package phase1;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1.Common.*;

/**
 *
 * @author younker/driscoll/garlow
 */
public class TestCase2 {

    public static void main(String[] args) {

        String case01 = "CASE #0_1 | Initialize Sender (Random Data) ";
        System.out.println(caseSeperator("*", case01));

        // true for using fixed msg, ks, and hash value, otherwise random data
        boolean fixedData = false;
        User amySender = createSender("Amy", fixedData);
        getRSAKeys(amySender);
        System.out.println("==> Sender's Status | " + amySender.toString() + "\n");

        String case02 = "CASE #0_2 | Initialize Receiver (Random Data) ";

        System.out.println(caseSeperator("*", case02));

        User bobReceiver = createReceiver("Bob");
        getRSAKeys(bobReceiver);

        System.out.println("==> Receiver's Status | " + bobReceiver.toString() + "\n");

        String case2 = "CASE #2: Suppose Sender wants to send a message to Receiver and Receiver wants to be sure that the message was indeed sent by the Sender.";

        System.out.println(caseSeperator("*", case2));

        String senderCase2 = "Sender Operations";
        System.out.println(caseSeperator("+", senderCase2));

        BigInteger cipher = senderCase2(amySender);

        System.out.println("==> Sender sends out cipher = | " + cipher + "\n");
        String receiverCase2 = "Receiver Operations";
        System.out.println(caseSeperator("+", receiverCase2));

        BigInteger msg = receiverCase2(amySender, bobReceiver, cipher);

        System.out.println("==> Receiver receives and decrypt msg = | " + msg + "\n");

    }

    public static void getRSAKeys(User user) {

        step++;
        System.out.println("\n--- Step #" + step + ": START - getRSAKeys()\t" + padding);

        int subStep = 1;

        System.out.println("--- Step #" + step + "-" + subStep + ": Run RSA " + "------------");

        Cryptography crypto = new Cryptography();

        subStep++;
        System.out.println("\n--- Step #" + step + "-" + subStep + ": Gets RSA keys" + "------------");

        //get pub and private keys
        BigInteger[] pub = new BigInteger[2];
        BigInteger[] priv = new BigInteger[2];
        
        crypto.getPublicKey(pub);
        crypto.getPrivateKey(priv);
        user.setPubKey(pub);
        user.setPrivateKey(priv);
        System.out.println(indent2 + "pubKey: " + Arrays.toString(user.getPubKey()));
        System.out.println(indent2 + "privateKey: " + Arrays.toString(user.getPrivateKey()));

        System.out.println("--- Step #" + step + ": END of getRSAKeys() \t" + padding + "\n");

    }

    public static User createSender(String name, boolean fixedData) {

        step++;
        System.out.println("\n--- Step #" + step + ": START - Sender generates\t" + padding);

        User s = new User(name, Role.SENDER, fixedData);
        System.out.println(indent2 + s.toString());
        System.out.println(indent2 + "Original message from sender = " + s.getMsg());
        System.out.println(indent2 + "Random session key = " + s.getKs());
        System.out.println(indent2 + "Hash function with base = " + s.getHashBase());
        
        System.out.println("--- Step #" + step + ": END of this Step \t\t" + padding + "\n");
        return s;
    }

    public static User createReceiver(String name) {

        step = 1;
        System.out.println("\n--- Step #" + step + ": START - Receiver generates\t" + padding);

        User r = new User(name, Role.RECEIVER);
        System.out.println(indent2 + r.toString());
        System.out.println(indent2 + "Original message from sender = " + r.getMsg());
        System.out.println(indent2 + "Random session key = " + r.getKs());
        System.out.println(indent2 + "Hash function with base = " + r.getHashBase());
        
        System.out.println("--- Step #" + step + ": END of this Step \t\t" + padding + "\n");
        return r;
    }

    public static void useCryptography(User user) {

        
        //what is this supposed to do?
        int subStep = 1;

        System.out.println("\n--- Step #" + step + "-" + subStep + ": Run RSA " + "------------");

        //TODO
    }

    //
    public static BigInteger receiverCase2(User sender, User receiver, BigInteger cipher) {
        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives cipher = " + cipher);
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should "
                + "decrypt the message with the senders public key (Pa+(cipher)-> message)");
        
        BigInteger m = receiverOperationsCase2(sender, cipher);
        
        return m;
    }
    private static BigInteger receiverOperationsCase2(User sender, BigInteger cipher) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase1 ----------------");
        BigInteger[] senderPublic = sender.getPubKey();
        BigInteger n = senderPublic[0];
        BigInteger e = senderPublic[1];
        BigInteger m = cipher.modPow(e, n);
        sender.setMsg(m);
        
        System.out.println(indent2 + "decrypted message = " + m);
        System.out.println(indent2 + "Receiver: " + sender.toString());
        
        System.out.println(indent2 + "------------------ End | receiverOperationsCase1 ----------------\n");
        return m;
    }

    public static BigInteger senderCase2(User sender) {

        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should "
                + "encrypt its message with its own public key (Pa-(Msg)-> cipher)"
                + " and send the encrypted message");
        BigInteger c = senderOperationsCase2(sender);

        return c;

    }

    private static BigInteger senderOperationsCase2(User sender) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase2 ----------------");

        //encrypt sender's msg with senders's private key
        BigInteger[] senderPrivate = sender.getPrivateKey();
        BigInteger n = senderPrivate[0];
        BigInteger d = senderPrivate[1];
        
        BigInteger c = sender.getMsg().modPow(d, n);
        System.out.println(indent2 + "Sender Private N = " + n);
        System.out.println(indent2 + "Sender Private D = " + d);
        System.out.println(indent2 + "cipher = " + c);
        
        System.out.println(indent2 + "------------------End | senderOperationsCase2 ----------------");

        return c;

    }

    

}

package phase1;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1.Common.*;

/**
 *
 * @author younker/driscoll/garlow
 */
public class TestCase1 {

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

        String case1 = "CASE #1: Suppose Sender wants to send a secret message to Receiver  using public key cryptography";

        System.out.println(caseSeperator("*", case1));

        String senderCase1 = "Sender Operations";
        System.out.println(caseSeperator("+", senderCase1));

        BigInteger cipher = senderCase1(amySender, bobReceiver);

        System.out.println("==> Sender sends out cipher = | " + cipher + "\n");
        String receiverCase1 = "Receiver Operations";
        System.out.println(caseSeperator("+", receiverCase1));

        BigInteger msg = receiverCase1(bobReceiver, cipher);

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

    //Suppose Bob wants to send a secret message to Alice using public key cryptography. 
    public static BigInteger receiverCase1(User receiver, BigInteger cipher) {
        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives cipher = " + cipher);
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should "
                + "decrypt the message with its own private key (Pb-(cipher)-> message)");
        
        BigInteger m = receiverOperationsCase1(receiver, cipher);
        
        return m;
    }

    public static BigInteger senderCase1(User sender, User receiver) {

        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should "
                + "encrypt its message with the receiver's public key (Pb+(Msg)-> cipher)"
                + " and send the encrypted message");
        BigInteger c = senderOperationsCase1(sender, receiver);
        //TODO
        return c;

    }

    private static BigInteger senderOperationsCase1(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase1 ----------------");

        //encrypt sender's msg with receiver's public key
        BigInteger[] recPub = receiver.getPubKey();
        BigInteger n = recPub[0];
        BigInteger e = recPub[1];
        
        BigInteger c = sender.getMsg().modPow(e, n);
        System.out.println(indent2 + "receiverPubN = " + n);
        System.out.println(indent2 + "receiverPubE = " + e);
        System.out.println(indent2 + "cipher = " + c);
        
        System.out.println(indent2 + "------------------End | senderOperationsCase1 ----------------");

        //TODO
        return c;

    }

    private static BigInteger receiverOperationsCase1(User receiver, BigInteger cipher) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase1 ----------------");
        BigInteger[] recPriv = receiver.getPrivateKey();
        BigInteger n = recPriv[0];
        BigInteger d = recPriv[1];
        BigInteger m = cipher.modPow(d, n);
        receiver.setMsg(m);
        
        System.out.println(indent2 + "decrypted message = " + m);
        System.out.println(indent2 + "Receiver: " + receiver.toString());
        
        System.out.println(indent2 + "------------------ End | receiverOperationsCase1 ----------------\n");
        return m;
    }

}

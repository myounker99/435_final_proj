package phase1;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1.Common.*;

/**
 *
 * @author younker/driscoll/garlow
 */
public class TestCase4 {

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

        String case2 = "CASE #4: Suppose Sender wants to send a secret messgae to Receiver, "
        		+ "and Receiver wants to be sure that the message wads indeeed sent by the Sender.";

        System.out.println(caseSeperator("*", case2));

        String senderCase4 = "Sender Operations";
        System.out.println(caseSeperator("+", senderCase4));

        BigInteger cipher = senderCase4(amySender, bobReceiver);

        System.out.println("==> Sender sends out cipher = | " + cipher + "\n");
        String receiverCase4 = "Receiver Operations";
        System.out.println(caseSeperator("+", receiverCase4));

        BigInteger msg = receiverCase4(amySender, bobReceiver, cipher);

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
    public static BigInteger receiverCase4(User sender, User receiver, BigInteger cipher) {
        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives cipher = " + cipher);
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should "
                + "decrypt the message with its own private key (Pb-(cipher)-> cipher)."
                + "It will then decrypt the message with the sender's public key Pa-(Pb+(cipher) -> Msg");
        
        BigInteger m = receiverOperationsCase4(sender, receiver, cipher);
        
        return m;
    }
    private static BigInteger receiverOperationsCase4(User sender, User receiver, BigInteger cipher) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase4 ----------------");
        
        //decrypt with the receiver's private key
        BigInteger[] rPriv = receiver.getPrivateKey();
        BigInteger n = rPriv[0];
        BigInteger d = rPriv[1];
        BigInteger m = cipher.modPow(d, n);
        System.out.println(indent2 + "Receiver Private N = " + n);
        System.out.println(indent2 + "Reciever Private D = " + d);
        System.out.println(indent2 + "Cipher message after decrypting with the receiver's private key = " + m);
        
        
        //then decrypt with the sender's public key
        BigInteger[] sPub = sender.getPubKey();
        BigInteger n2 = sPub[0];
        BigInteger e = sPub[1];
        BigInteger msg = m.modPow(e, n2);
        System.out.println(indent2 + "Sender Public N = " + n2);
        System.out.println(indent2 + "Sender Public E = " + e);
        System.out.println(indent2 + "decrypted message = " + msg);
        
        if(sender.getMsg().equals(msg))
        {
        	System.out.println(indent2 + "The message from thesender(" + sender.getMsg() +") is equal to the message("+ msg +  ") the receiver received");
        }
        else
        {
        	System.out.println(indent2 + "The message from the sender(" + sender.getMsg() +") is NOT equal to the message("+ msg +  ") the receiver received");
        	
        }
        receiver.setMsg(msg);

        System.out.println(indent2 + "Receiver: " + sender.toString());
        
        System.out.println(indent2 + "------------------ End | receiverOperationsCase4 ----------------\n");
        return msg;
    }

    public static BigInteger senderCase4(User sender, User receiver) {

        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should "
                + "encrypt its message with its own private key (Pa-(Msg)-> cipher)."
                + "It will then encrypt that with the Receiver's public Key Pb+(Pa-(msg)) -> cipher "
                + "and send the encrypted message");
        BigInteger c = senderOperationsCase4(sender, receiver);

        return c;

    }

    private static BigInteger senderOperationsCase4(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase4 ----------------");

        //encrypt with the sender's private key
        BigInteger[] senderPrivate = sender.getPrivateKey();
        BigInteger n = senderPrivate[0];
        BigInteger d = senderPrivate[1];
        
        BigInteger c1 = sender.getMsg().modPow(d, n);
        System.out.println(indent2 + "Sender Private N = " + n);
        System.out.println(indent2 + "Sender Private D = " + d);
        System.out.println(indent2 + "cipher encrypted sender private key = " + c1);
        
        //then encrypt with the receiver's public key
        BigInteger[] rPub = receiver.getPubKey();
        BigInteger n2 = rPub[0];
        BigInteger e = rPub[1];
        
        BigInteger c2 = c1.modPow(e, n2);
        System.out.println(indent2 + "Receiver Public N = " + n2);
        System.out.println(indent2 + "Receiver Public E = " + e);
        System.out.println(indent2 + "cipher encrypted sender private key and then receiver public key= " + c2);
        
        System.out.println(indent2 + "------------------End | senderOperationsCase4 ----------------");

        return c2;

    }

    

}

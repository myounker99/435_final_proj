/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package phase1;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1.Common.*;

/**
 *
 * @author younker/driscoll/garlow
 */
public class TestCase3 {
    
    public static void main(String[] args)
    {
        String case01 = "Case #0_1 | Initialize Sender (Random Data)";
        System.out.println(caseSeperator("*", case01));
        
        boolean fixedData = false;
        User amySender = createSender("Amy", fixedData);
        getRSAKeys(amySender);
        System.out.println("==> Sender's Status | " + amySender.toString() + "\n");

        
        String case02 = "Case #0_2 | Initialize Receiver (Random Data)";
        System.out.println(caseSeperator("*", case02));
        User bobReceiver = createReceiver("Bob");
        getRSAKeys(bobReceiver);
        System.out.println("==> Receiver's Status | " + bobReceiver.toString() + "\n");
        
        String case3 = "CASE #3: Suppose Sender wants to send a secret message to Receiver"
                + " and Receiver wants to verify the integrity of the message";

        System.out.println(caseSeperator("*", case3));
        
        String senderCase3 = "Sender Operations";
        System.out.println(caseSeperator("+", senderCase3));
        
        BigInteger[] encryptedPayload = new BigInteger[3];
        senderCase3(amySender, bobReceiver, encryptedPayload);
        
        System.out.println("\n==> Sender sender out payload = | " + Arrays.toString(encryptedPayload) + "\n");
        String recCase3 = "Receiver Operations";
        System.out.println(caseSeperator("+", recCase3));
        
        receiverCase3(bobReceiver, encryptedPayload);
        
        System.out.println("==> Receiver receives, decrypts, and verfies the integrity of msg = | " + bobReceiver.getMsg() + "\n");
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
    
    public static void senderCase3(User sender, User receiver, BigInteger[] payload) {

        int subStep = 0;

        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should "
                + "hash the symmetric key + message to get H(Ks+m) and then "
                + "use the symmetric key to encrypt to get Ks(H(Ks+m)+m)."
                + " This ensures that the message is secret and the "
                + "receiver can check the integrity");
        senderOperationsCase3(sender, receiver, payload);
    }
    
    private static void senderOperationsCase3(User sender, User receiver, BigInteger[] payload) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase3 ----------------");

        //assume sender and receiver establish the same Ks and hash base
        receiver.setHashBase(sender.getHashBase());
        receiver.setKs(sender.getKs());

        
        String append = receiver.getKs().toString() + sender.getMsg().toString();
//	    System.out.println("Ks: " + receiver.getKs());
//	    System.out.println("Msg: " + sender.getMsg().toString());
//	    System.out.println("Append: " + append);
        BigInteger converted = new BigInteger(append);
        
        //payload[0] = [0] = Ks(H(Ks + m)), [1] = Ks[m]   
        payload[0] = Cryptography.shift(Cryptography.hash(converted, sender.getHashBase()),sender.getKs());
        payload[1] = Cryptography.shift(sender.getMsg(), sender.getKs());

        
        //System.out.println(indent2 + "Encrypted MAC part 1 ----- Ks(H(Ks)) = " + payload[0]);
        System.out.println(indent2 + "Encrypted MAC ----- Ks(H(Ks+m)) = " + payload[0]);
        System.out.println(indent2 + "Encrypted message -------- Ks(m) = " + payload[1]);
        
        System.out.println(indent2 + "------------------End | senderOperationsCase3 ----------------");
    }
    
    public static void receiverCase3(User receiver, BigInteger[] encryptedPayload) {
        int subStep = 0;
        
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + "Assume the symmetric key and hash base have been established");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives payload = " + Arrays.toString(encryptedPayload));
        
        subStep++;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should "
                + "decrypt the payload with the symmetric key Ks(H(Ks+m)+m) -> H(Ks+m)+m "
                + "and then compute its own MAC with m to compare to the sender's MAC");
        
        BigInteger[] decryptedPayload = new BigInteger[2];
        receiverOperationsCase3(receiver, encryptedPayload, decryptedPayload);
    
    }
    
    private static void receiverOperationsCase3(User receiver, BigInteger[] encryptedPayload, BigInteger[] decryptedPayload) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase1 ----------------");
        
        //shift all values back
        //decryptedPayload[0] = Cryptography.shiftBack(encryptedPayload[0], receiver.getKs());
        decryptedPayload[0] = Cryptography.shiftBack(encryptedPayload[0], receiver.getKs());
        decryptedPayload[1] = Cryptography.shiftBack(encryptedPayload[1], receiver.getKs());
        
        String append = receiver.getKs().toString() + decryptedPayload[1].toString();
//        System.out.println("Ks: " + receiver.getKs());
//        System.out.println("Msg: " + decryptedPayload[1].toString());
//        System.out.println("Append: " + append);
        
        BigInteger converted = new BigInteger(append);
        
        //check if calculated MAC equal received MAC
        BigInteger[] calculatedMAC = new BigInteger[2];
        
        calculatedMAC[0] = Cryptography.hash(converted, receiver.getHashBase());
        
        System.out.println(indent2 + "received MAC = " + decryptedPayload[0]);
        System.out.println(indent2 + "calculated MAC = " + calculatedMAC[0]);
                
        if(decryptedPayload[0].equals(calculatedMAC[0]))
        {
            System.out.println("\n" + indent2 + "===== Message Authenticated =====");
            receiver.setMsg(decryptedPayload[1]);
        }
        else
        {
            System.out.println("\n" + indent2 + "===== Message NOT Authenticated =====");
        }
        
        System.out.println(indent2 + "decrypted message = " + receiver.getMsg());
        
        System.out.println(indent2 + "------------------ End | receiverOperationsCase1 ----------------\n");
    }
}

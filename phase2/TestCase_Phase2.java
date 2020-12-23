package Phase2;

import java.math.BigInteger;
import java.util.Arrays;
import static Phase2.Common.*;

/**
 *
 * @author younker/driscoll/garlow
 */
public class TestCase_Phase2 {

    public static void main(String[] args) {
    	
    	//----------- Setup Begin 
        String case01 = "CASE #0_1 | Initialize Sender (Random Data) ";
        System.out.println(caseSeperator("*", case01));

        
        boolean fixedData = false;	// true for using fixed msg, ks, and hash value, otherwise random data
        boolean hack = true;		//true means that the packet will be hacked, false means it will not be hacked
        User amySender = createSender("Amy", fixedData);
        getRSAKeys(amySender);
        System.out.println("==> Sender's Status | " + amySender.toString() + "\n");

        String case02 = "CASE #0_2 | Initialize Receiver (Random Data) ";

        System.out.println(caseSeperator("*", case02));

        User bobReceiver = createReceiver("Bob");
        getRSAKeys(bobReceiver);

        System.out.println("==> Receiver's Status | " + bobReceiver.toString() + "\n");

        //----------- Setup End 
        
        String case1 = "Phase 2: Simulate the sending and receiving of a secure message over the internet";
        System.out.println(caseSeperator("*", case1));

        //----------- Sender Begin
        
        String senderCase1 = "Start of Sender Operations";
        System.out.println(caseSeperator("+", senderCase1));

        Packet pk = senderCase1(amySender, bobReceiver);

        System.out.println(indent1 + "Step 8: Packet to be sent on to the network is:");
        System.out.println(indent2 + "Cipher Ks+(m): " + pk.getEMsg());
        System.out.println(indent2 + "Digital Signature Ks(Pa-H(m))): " + pk.getEDS());
        System.out.println(indent2 + "Encrypted Ks Pb+(Ks): " + pk.getEKs() + "\n");
        
        String senderCase2 = "End of Sender Operations";
        System.out.println(caseSeperator("+", senderCase2));
        
        //----------- Sender End 
        //----------- Network Begin
        
        Network nt = new Network();
        
        nt.pkInFromSender(pk);
        if(hack)
        {
        	nt.pkGetHacked();
        }
        nt.pkOutToReceiver();
        
        //----------- Network End
        //----------- Receiver Begin
        
        String receiverCase1 = "Start of Receiver Operations";
        System.out.println(caseSeperator("+", receiverCase1));

        BigInteger msg = receiverCase1(amySender, bobReceiver, pk);

        
        String receiverCase2 = "End of Receiver Operations";
        System.out.println(caseSeperator("+", receiverCase2));

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
        
        //sets the public key and private key to the user
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

    //Suppose Bob wants to send a secret message to Alice using public key cryptography. 
   

    public static Packet senderCase1(User sender, User receiver) {
	
        int step = 1;

        //outputs the message to be sent
        System.out.println(indent1 + "Step #" + step + ": Get the message. (m)");
        BigInteger msg = sender.getMsg();
        System.out.println(indent2 + "Sender's message = " + msg + "\n");
        step++;
        
        //hashes the message and then turns it into a digital signature
        BigInteger hashedDS = senderOperationsCase1(sender, step);
        step += 2;
        
        //gets the session key
        System.out.println(indent1 + "Step #" + step + ": Get the session key. (Ks)");
        BigInteger Ks = sender.getKs();
        System.out.println(indent2 + "Session Key = " + Ks + "\n");
        step++;
        
        //encrypts the session key with the receiver's public key
        BigInteger encryptKs = Cryptography.modPower(receiver.pubKey, Ks);
        System.out.println(indent1 + "Step #" + step + ": Encrypt the Session key. Pb+(Ks)");
        System.out.println(indent2 + "Encrypted Session key = " + encryptKs + "\n");
        step++;
        
        //encrypts the msg and the digital signature with the session key
        BigInteger[] encryptMsgDS = senderOperationsCase2(Ks, msg, hashedDS, step);
        step += 2;
        
        Packet pk = new Packet(encryptMsgDS[0], encryptMsgDS[1], encryptKs, sender.getHashBase());
        
        return pk;

    }

    //hashes the message and then turns it into a digital signature
    private static BigInteger senderOperationsCase1(User sender, int step) {

    	BigInteger hashMsg= Cryptography.hash(sender.getMsg(), sender.getHashBase());		//hashes the msg
        System.out.println(indent1 + "Step #" + step + ": Hash the message. H(m)");
        System.out.println(indent2 + "Hashed message = " + hashMsg + "\n");
        step++;
               
        BigInteger DS = Cryptography.modPower(sender.privateKey, hashMsg);	//encrypts with sender's private key to make a digital signature
        System.out.println(indent1 + "Step #" + step + ": Encrypt with sender's private key. Pa-(H(m))");
        System.out.println(indent2 + "Sender's digital signature = " + DS + "\n");
        step++;
        
        return DS;

    }
    
    //encrypts the msg and the digital signature with the session key
    private static BigInteger[] senderOperationsCase2(BigInteger Ks, BigInteger msg, BigInteger DS, int step) {

    	BigInteger[] encrypted = new BigInteger[2];

    	//encrypts the message with the symmetric key
    	encrypted[0] = Cryptography.shift(msg, Ks);
        System.out.println(indent1 + "Step #" + step + ": Encrypt the message with Ks. Ks+(m)");
        System.out.println(indent2 + "Encrypted Message = " + encrypted[0] + "\n");
        step++;
               
        //encrypts the digital signature with the symmetric key
        encrypted[1] = Cryptography.shift(DS, Ks);
        System.out.println(indent1 + "Step #" + step + ": Encrypt the DS with Ks. Ks+(Pa-H(m))");
        System.out.println(indent2 + "Encrypted DS = " + encrypted[1] + "\n");
        step++;

        return encrypted;

    }
    
    
    public static BigInteger receiverCase1(User sender, User receiver, Packet pk) {
        
    	int step = 1;

        //outputs the message to be sent
        System.out.println(indent1 + "Step #" + step + ": Received packet from Network Packet.\n");
        step++;
        
        //ouputs the contents of the packet
        System.out.println(indent1 + "Step #" + step + ": Split up the packet.");
        System.out.println(indent2 + "Cipher Ks(m): " + pk.getEMsg());
        System.out.println(indent2 + "Digital Signature Ks(Pa-(H(m))): " + pk.getEDS());
        System.out.println(indent2 + "Encrypted Ks  Pb+(Ks): " + pk.getEKs() + "\n");
        step++;       
        
        //decrypts the session key using the receiver's private key
        BigInteger decryptKs = Cryptography.modPower(receiver.privateKey, pk.getEKs());
        System.out.println(indent1 + "Step #" + step + ": Decrypt Session key. Pb-(Pb+(Ks))");
        System.out.println(indent2 + "Session key = " + decryptKs + "\n");
        step++;
    	
        //decrypts the msg and the digital signature with the session key
        BigInteger[] decryptMsgDS = receiverOperationsCase1(decryptKs, pk.getEMsg(), pk.getEDS(), step);
        step +=2;
        
        //hashes the msg that was just decrypted
        BigInteger hashMsg= Cryptography.hash(decryptMsgDS[0], pk.getHashBase());		
        System.out.println(indent1 + "Step #" + step + ": Hash the message. H(m) = V");
        System.out.println(indent2 + "Hashed message = " + hashMsg + "\n");
        step++;
        
        //decrypts the Digital Signature to get the hash value
        BigInteger decryptHash = Cryptography.modPower(sender.getPubKey(), decryptMsgDS[1]);
        System.out.println(indent1 + "Step #" + step + ": Decrypt the received digital signature. Pa+(Pa-(H(m))) = X");
        System.out.println(indent2 + "Decrypted Hash = " + decryptHash + "\n");
        step++;
        
        //compare the two hashes
        System.out.println(indent1 + "Step #" + step + ": Compare Hashes. V == X?");
        
        if(hashMsg.equals(decryptHash))	
        {
        	//if the hashes equal each other
        	System.out.println(indent2 + "The two hashes are equal to each other so the packet is accepted. V == X ---- yes");
        }
        else		
        {
        	//if they do not equal each other
        	System.out.println(indent2 + "The two hashes are NOT equal to each other so the packet is discarded. V == X ---- no");
        }
        
        receiver.setMsg(decryptMsgDS[0]);
        return receiver.getMsg();
    }

    //encrypts the msg and the digital signature with the session key
    private static BigInteger[] receiverOperationsCase1(BigInteger Ks, BigInteger msg, BigInteger DS, int step) {

    	BigInteger[] dMsgDS = new BigInteger[2];
    	
    	//decrypts the message with the session key
    	dMsgDS[0] = Cryptography.shiftBack(msg, Ks);
        System.out.println(indent1 + "Step #" + step + ": Decrypt the encrypted message with Ks. Ks-(Ks+(m)) ");
        System.out.println(indent2 + "Decrypted Message = " + dMsgDS[0] + "\n");
        step++;
               
        //decrypts the digital signature with the session key
        dMsgDS[1] = Cryptography.shiftBack(DS, Ks);
        System.out.println(indent1 + "Step #" + step + ": Decrypt the encrypted DS with Ks. Ks-(Ks+(Pa-(H(m))))");
        System.out.println(indent2 + "Decrypted DS = " + dMsgDS[1] + "\n");
        step++;
    	
        return dMsgDS;
    }

}

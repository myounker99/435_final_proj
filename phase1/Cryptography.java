package phase1;

import java.math.BigInteger;
import static phase1.Common.*;

/**
 *
 * @author younker/driscoll/garlow
 */
public class Cryptography {

    private RSA rsa;

    Cryptography() {

        System.out.println(indent2 + "Run Cryptography --------");
        
        rsa = new RSA();
        System.out.println(indent2 + rsa.toString());
        //TODO

    }

   
    // Use the mapping provided in our ICE, and you can modify the header of this method
    static public BigInteger CBC() {
     
        //TODO
        return BigInteger.ZERO;
    }

    static public BigInteger hash(BigInteger msg, BigInteger hashBase) {
        BigInteger msgCopy = msg;
        BigInteger hashValue = msgCopy.mod(hashBase);
        return hashValue;
    }

    static public BigInteger shift(BigInteger msg, BigInteger ks) {
        //TODO        
        
        return msg.add(ks);
    }
    
    //so receiver can decrypt
    static public BigInteger shiftBack(BigInteger msg, BigInteger ks)
    {
        return msg.subtract(ks);
    }

    //(n, e)
    public void getPublicKey(BigInteger[] pubKey) {
       pubKey[0] = rsa.getN();
       pubKey[1] = rsa.getE();
    }

    // (n, d)
    public void getPrivateKey(BigInteger[] privateKey) {
       privateKey[0] = rsa.getN();
       privateKey[1] = rsa.getD();
    }

}

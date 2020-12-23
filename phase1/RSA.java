package phase1;

import java.math.BigInteger;
import java.util.Random;

/**
 *
 * @author younker/driscoll/garlow
 */
public class RSA {

    private BigInteger p, q, n, z, e, d;

 

    RSA() {

        runRSA();

    }

    @Override
    public String toString() {
        return "RSA{" + "p=" + p + ", q=" + q + ", n=" + n + ", z=" + z + ", e=" + e + ", d=" + d + '}';
    }

    /**
     * adapted and modified
     * https://www.sanfoundry.com/java-program-implement-rsa-algorithm/
     */
    private void runRSA() {

        Random r = new Random();
        int bitlength = 16;

        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        n = p.multiply(q);
        z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        setE(BigInteger.probablePrime(bitlength / 2, r));

        while (z.gcd(getE()).compareTo(BigInteger.ONE) > 0 && getE().compareTo(z) < 0) {
            getE().add(BigInteger.ONE);
        }
        setD(getE().modInverse(z));

    }

    /**
     *
     * @return
     */
    public BigInteger getN() {
        return n;
    }

    /**
     *
     * @return
     */
    public BigInteger getE() {
        return e;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    /**
     *
     * @param e
     */
    public void setE(BigInteger e) {
        this.e = e;
    }

    /**
     *
     * @return
     */
    public BigInteger getD() {
        return d;
    }

    /**
     *
     * @param d
     */
    public void setD(BigInteger d) {
        this.d = d;
    }

}

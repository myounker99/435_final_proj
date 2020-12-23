package Phase2;

import java.math.BigInteger;

/**
 *
 * @author younker/driscoll/garlow
 */
public class Network {

    Packet pk;
    String netStr = "|                                 |";



    public void pkInFromSender(Packet _pk) {

        System.out.println("\n\n|     START of the Internet       |");

        for (int i = 1; i < 3; i++) {

            System.out.println(netStr);

        }
        System.out.println("     packet in transmission  ");

        for (int i = 1; i < 3; i++) {

            System.out.println(netStr);

        }

        this.pk = _pk;

    }

    ;
    
    public void pkGetHacked() {

        System.out.println("XXXXX   packet gets hacked   XXXXXX");

        BigInteger cipher = this.pk.getCipher();

        this.pk.setCipher(cipher.add(BigInteger.TEN));

    }

    public Packet pkOutToReceiver() {

        for (int i = 1; i < 3; i++) {

            System.out.println(netStr);

        }
        System.out.println("       packet arrives        ");

        for (int i = 1; i < 3; i++) {

            System.out.println(netStr);

        }
        System.out.println("|     END of the Internet         |\n\n");
        return this.pk;

    }

}

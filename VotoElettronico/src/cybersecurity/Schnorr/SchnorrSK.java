package cybersecurity.Schnorr;

import java.io.Serializable;
import java.math.BigInteger;

public class SchnorrSK implements Serializable {
    public BigInteger p,q,g,s;
    public int securityparameter;

    public SchnorrSK(BigInteger p, BigInteger q, BigInteger g, BigInteger s, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.s = s;
        this.securityparameter = securityparameter;
    }
}
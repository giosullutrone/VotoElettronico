package cybersecurity.Schnorr;

import java.io.Serializable;
import java.math.BigInteger;

public class SchnorrPK implements Serializable {
    public BigInteger g,h,p,q;
    public int securityparameter;

    public SchnorrPK(BigInteger p,BigInteger q,BigInteger g,BigInteger h,int securityparameter) {
        this.p=p;
        this.q=q;
        this.g=g;
        this.h=h;
        this.securityparameter=securityparameter;					
    }
}
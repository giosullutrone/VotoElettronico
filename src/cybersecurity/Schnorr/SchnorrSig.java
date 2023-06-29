package cybersecurity.Schnorr;

import cybersecurity.ElGamal.ElGamal;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SchnorrSig implements Serializable {
    public BigInteger a, e, z;
    
    public SchnorrSig(BigInteger a,BigInteger e,BigInteger z) {
        this.a=a;
        this.e=e;
        this.z=z;
    }
    
    public SchnorrSig encode(ElGamal elGamal, PublicKey PK) throws Exception {
        return new SchnorrSig(new BigInteger(elGamal.encode(a.toByteArray(), PK)),
                              new BigInteger(elGamal.encode(e.toByteArray(), PK)),
                              new BigInteger(elGamal.encode(z.toByteArray(), PK)));
    }
    
    public SchnorrSig decode(ElGamal elGamal, PrivateKey SK) throws Exception {
        return new SchnorrSig(new BigInteger(elGamal.decode(a.toByteArray(), SK)),
                              new BigInteger(elGamal.decode(e.toByteArray(), SK)),
                              new BigInteger(elGamal.decode(z.toByteArray(), SK)));
    }
}
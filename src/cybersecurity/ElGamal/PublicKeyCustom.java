package cybersecurity.ElGamal;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class PublicKeyCustom implements Serializable {
    private final PublicKey publicKey;
    private final BigInteger h;

    public PublicKeyCustom(PublicKey publicKey, BigInteger h) {
        this.publicKey = publicKey;
        this.h = h;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getH() {
        return h;
    }
}

package cybersecurity.ElGamal;

import java.io.Serializable;
import java.security.PrivateKey;

public class KeyPairCustom implements Serializable{
    private final PublicKeyCustom publicKeyCustom;
    private final PrivateKey privateKey;

    public KeyPairCustom(PublicKeyCustom publicKeyCustom, PrivateKey privateKey) {
        this.publicKeyCustom = publicKeyCustom;
        this.privateKey = privateKey;
    }
    
    public PublicKeyCustom getPublic() {
        return publicKeyCustom;
    }

    public PrivateKey getPrivate() {
        return privateKey;
    }
}

package cybersecurity.Primitives;

import java.io.Serializable;
import java.security.PublicKey;

public  class BCCredential implements Serializable{
    private final String cf;
    private final PublicKey pk;

    public BCCredential(String cf, PublicKey pk) {
        this.cf = cf;
        this.pk = pk;
    }

    public String getCf() {
        return cf;
    }

    public PublicKey getPK() {
        return pk;
    }
}

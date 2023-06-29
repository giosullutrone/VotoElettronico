package cybersecurity.Primitives;

import cybersecurity.ElGamal.ElGamal;
import cybersecurity.Schnorr.SchnorrSig;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

public class VoteCredential implements Serializable{
    private final byte[] R;
    private final SchnorrSig sigMI;
    private final SchnorrSig sigMD;

    public VoteCredential(byte[] R, SchnorrSig sigMI, SchnorrSig sigMD) {
        this.R = R;
        this.sigMI = sigMI;
        this.sigMD = sigMD;
    }

    public byte[] getR() {
        return R;
    }

    public SchnorrSig getSigMI() {
        return sigMI;
    }

    public SchnorrSig getSigMD() {
        return sigMD;
    }
    
    public VoteCredential encode(ElGamal elGamal, PublicKey PK) throws Exception {
        return new VoteCredential(elGamal.encode(R, PK),
                                  sigMI.encode(elGamal, PK), 
                                  sigMD.encode(elGamal, PK));
    }
    
    public VoteCredential decode(ElGamal elGamal, PrivateKey SK) throws Exception {
        return new VoteCredential(elGamal.decode(R, SK),
                                  sigMI.decode(elGamal, SK), 
                                  sigMD.decode(elGamal, SK));
    }
}
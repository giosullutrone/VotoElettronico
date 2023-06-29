package cybersecurity.Primitives;

import cybersecurity.ElGamal.ElGamal;
import cybersecurity.Schnorr.SchnorrSig;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;

public class ShareCypher implements Serializable{
    public int i;
    public byte[] cyphershare;
    public byte[] cyphersignaturept1;
    public byte[] cyphersignaturept2;
    public byte[] cyphersignaturept3;

    public ShareCypher(ElGamal elGamal, SchnorrSig sigma, PublicKey key, BigInteger secret, int i) throws Exception {
        this.i=i;
        this.cyphershare=elGamal.encode(secret.toByteArray(), key);
        
        this.cyphersignaturept1=sigma.a.toByteArray();
        this.cyphersignaturept1=elGamal.encode(this.cyphersignaturept1, key); 
        
        this.cyphersignaturept2=sigma.e.toByteArray();
        this.cyphersignaturept2=elGamal.encode(this.cyphersignaturept2, key);
        
        this.cyphersignaturept3=sigma.z.toByteArray();
        this.cyphersignaturept3 =elGamal.encode(this.cyphersignaturept3, key);
        System.out.println("Secret share no." + i + ", the  share: " + cyphershare.toString()+ " signature :"+cyphersignaturept1.toString() + " "+ cyphersignaturept2.toString() + " "+ cyphersignaturept3.toString() +"\n");
    }
    
    public ShareCypher(int i, byte[] cypher, byte[] sigcypher1, byte[] sigcypher2, byte[] misigcypher3) {
        this.i= i;
        this.cyphershare= cypher;
        this.cyphersignaturept1= sigcypher1;
        this.cyphersignaturept2= sigcypher2;
        this.cyphersignaturept3= misigcypher3;
    }
}

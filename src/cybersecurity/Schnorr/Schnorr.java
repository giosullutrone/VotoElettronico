package cybersecurity.Schnorr;

import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Utils.Utils;
import java.io.Serializable;
import java.math.*;
import java.security.*;

public class Schnorr implements Serializable {
    public static BigInteger HashToBigInteger(SchnorrPK PK, BigInteger a, String M) {
        // Hash PK+a+M to a BigInteger
        String msg = PK.g.toString() + PK.h.toString() + a.toString() + M;
        try { // hash a String using MessageDigest class
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update(Utils.toByteArray(msg));
            BigInteger e = new BigInteger(h.digest());

            return e.mod(PK.q);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        BigInteger e = new BigInteger("0");
        return e;
    }

    public static SchnorrSig Sign(PublicKeyCustom PK, PrivateKey SK, String M){
        SchnorrPK schnorrPK = getSchnorrPK(PK.getPublicKey(), PK.getH());
        SchnorrSK schnorrSK = getSchnorrSK(PK.getPublicKey(), SK, PK.getH());
        
        SecureRandom sc = new SecureRandom(); // generate secure random source
        BigInteger r = new BigInteger(schnorrSK.securityparameter, sc); // choose random r
        BigInteger a = schnorrSK.g.modPow(r, schnorrSK.p); // a=g^r mod p
        BigInteger e = HashToBigInteger(schnorrPK, a, M); // e=H(PK,a,M)
        BigInteger z = r.add(e.multiply(schnorrSK.s).mod(schnorrSK.q)).mod(schnorrSK.q); // z=r+es mod q
        return new SchnorrSig(a, e, z); // (a,e,z) is the signature of M
    }

    public static boolean Verify(SchnorrSig sigma, PublicKeyCustom PK, String M) {
        SchnorrPK schnorrPK = getSchnorrPK(PK.getPublicKey(), PK.getH());
        
        // sigma is the triple (a,e,z), PK is the pair (g,h)
        BigInteger e2 = HashToBigInteger(schnorrPK, sigma.a, M); // e2=H(PK,a,M)
        // crucial that we use the hash computed by ourself and not the challenge e in the signature
        // actually the value e in the signature is NOT needed
        BigInteger tmp = sigma.a.multiply(schnorrPK.h.modPow(e2, schnorrPK.p)).mod(schnorrPK.p); // tmp=ah^e2
        return (tmp.compareTo(schnorrPK.g.modPow(sigma.z, schnorrPK.p)) == 0);
    }
    
    private static SchnorrPK getSchnorrPK(PublicKey publicKey, BigInteger h) {
        return new SchnorrPK(ElGamal.getP(publicKey), ElGamal.getQ(publicKey), 
                             ElGamal.getG(publicKey), h,
                             ElGamal.SECURITYPARAMETER);
    }
    
    private static SchnorrSK getSchnorrSK(PublicKey publicKey, PrivateKey privateKey, BigInteger h) {   
        return new SchnorrSK(ElGamal.getP(publicKey), ElGamal.getQ(publicKey), 
                             ElGamal.getG(publicKey), ElGamal.getX(privateKey),
                             ElGamal.SECURITYPARAMETER);
    }
}
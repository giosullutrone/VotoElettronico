package cybersecurity;

import cybersecurity.Primitives.ShareCypher;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Utils.UtilsFile;
import cybersecurity.Schnorr.SchnorrSig;
import cybersecurity.Schnorr.Schnorr;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.SecureRandom;

public class SecretSharing {
    private static BigInteger q;
    private static final int size = 512;
    
    private static final String[] minFiles = new String[] {"miShare.txt", 
                                                           "mdShare.txt",
                                                           "mitdShare.txt",
                                                           "mpaShare.txt"};
    
    public static void main(String[] args) throws Exception {
        //1)	Generiamo una coppia (PK, SK) di ElGamalCustom
        ElGamal elGamal = new ElGamal();
        KeyPairCustom keyPair = elGamal.generateKeyPair();
        PublicKeyCustom publicKeyCustom = keyPair.getPublic();
        PublicKey publicKey = publicKeyCustom.getPublicKey();
        PrivateKey privateKey = keyPair.getPrivate();

        q=ElGamal.getP(publicKey);
        BigInteger s=ElGamal.getX(privateKey);
        //2)	Salviamo su file la PK generata
        UtilsFile.PublicKeyToFile("PublicKey.txt", publicKeyCustom);
        
        //3)	Recuperiamo da file le chiavi di ElGamal dei ministeri [Semplificazione: Caricato l’intera coppia di chiavi]
        KeyPairCustom[] keyPairs = new KeyPairCustom[4];
        keyPairs[0] = UtilsFile.keyPairFromFile("miKp.txt");
        keyPairs[1] = UtilsFile.keyPairFromFile("mdKp.txt");
        keyPairs[2] = UtilsFile.keyPairFromFile("mitdKp.txt");
        keyPairs[3] = UtilsFile.keyPairFromFile("mpaKp.txt");
        
        //4)	Generiamo le share di Shamir Secret Sharing
        SecureRandom sc = new SecureRandom();
        BigInteger a = (new BigInteger(size, sc)).mod(q); // choose random a in Fq
        BigInteger b = (new BigInteger(size, sc)).mod(q); // choose random b in Fq
        // We have the polynomial p(X)=aX^2+bX+s
        BigInteger[] secretshares = new BigInteger[4]; // this is the array that will contain the shares to send to each participant
        
        for (int i = 0; i < 4; i++) {
            //5)	Firmiamo le share con la chiave segreta di ElGamalCustom (Per motivi di compatibilità)
            secretshares[i] = a.multiply(a.multiply(BigInteger.valueOf(i + 1))).add(b.multiply((BigInteger.valueOf(i + 1)))).add(s).mod(q); // secretshares[i]=a(i+1)+s mod q
            
            //6)	Criptiamo le share e le firme con le chiavi del rispettivo ministero
            SchnorrSig sigma = Schnorr.Sign(keyPair.getPublic(), privateKey, secretshares[i].toString());

            ShareCypher shareCypher=new ShareCypher(elGamal, sigma, keyPairs[i].getPublic().getPublicKey(), secretshares[i], i);
            //7)	Mostriamo i risultati a schermo e li salviamo su file
            UtilsFile.ShareCypherToFile(minFiles[i], shareCypher);
        }
    }
}

package cybersecurity;

import cybersecurity.Primitives.ShareCypher;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Utils.UtilsFile;
import java.math.BigInteger;
import java.security.PrivateKey;

public class SecretReconstruction {
    public static PrivateKey Reconstruct() throws Exception {
        BigInteger si1, si2, si3, q;
        int i1, i2, i3;
        
        //RECUPERO DATI DA FILE
        ShareCypher shareMI = UtilsFile.ShareCypherFromFile("miShare.txt");
        ShareCypher shareMITD = UtilsFile.ShareCypherFromFile("mitdShare.txt");
        ShareCypher shareMD = UtilsFile.ShareCypherFromFile("mdShare.txt");
        ShareCypher shareMPA = UtilsFile.ShareCypherFromFile("mpaShare.txt");
        
        KeyPairCustom keysMI = UtilsFile.keyPairFromFile("miKp.txt");
        KeyPairCustom keysMITD = UtilsFile.keyPairFromFile("MitdKp.txt");
        KeyPairCustom keysMD = UtilsFile.keyPairFromFile("mdKp.txt");
        KeyPairCustom keysMPA = UtilsFile.keyPairFromFile("mpaKp.txt");
        
        //DECRIPT THE SHARE
        ElGamal el = new ElGamal();
        byte[] cleanshareMI = el.decode(shareMI.cyphershare, keysMI.getPrivate());
        byte[] cleanshareMITD = el.decode(shareMITD.cyphershare, keysMITD.getPrivate());
        byte[] cleanshareMD = el.decode(shareMD.cyphershare, keysMD.getPrivate());
        byte[] cleanshareMPA = el.decode(shareMPA.cyphershare, keysMPA.getPrivate());
        
        PublicKeyCustom H = UtilsFile.PublicKeyFromFile("PublicKey.txt");
        q=ElGamal.getP(H.getPublicKey());
        
        //WE USE 3 OF THEM AND SO WE USE MI, MITD AND MD
        si1= new BigInteger(cleanshareMI);
        i1 = shareMI.i + 1;
        si2 = new BigInteger(cleanshareMITD);
        i2 = shareMITD.i + 1;
        si3 = new BigInteger(cleanshareMD);
        i3 = shareMD.i + 1;
        
        //CALCOLO RISULTATO SECRET SHARING
        BigInteger Lambdai1, Lambdai2, Lambdai3, tmp, tmp1;

        tmp = BigInteger.valueOf(i2).subtract(BigInteger.valueOf(i1)).modInverse(q);
        tmp = BigInteger.valueOf(i2).multiply(tmp).mod(q);
        tmp1 = BigInteger.valueOf(i3).subtract(BigInteger.valueOf(i1)).modInverse(q);
        tmp1 = BigInteger.valueOf(i3).multiply(tmp1).mod(q);
        Lambdai1 = tmp.multiply(tmp1);

        tmp = BigInteger.valueOf(i1).subtract(BigInteger.valueOf(i2)).modInverse(q);
        tmp = BigInteger.valueOf(i1).multiply(tmp).mod(q);
        tmp1 = BigInteger.valueOf(i3).subtract(BigInteger.valueOf(i2)).modInverse(q);
        tmp1 = BigInteger.valueOf(i3).multiply(tmp1).mod(q);
        Lambdai2 = tmp.multiply(tmp1);
        
        tmp = BigInteger.valueOf(i1).subtract(BigInteger.valueOf(i3)).modInverse(q);
        tmp = BigInteger.valueOf(i1).multiply(tmp).mod(q);
        tmp1 = BigInteger.valueOf(i2).subtract(BigInteger.valueOf(i3)).modInverse(q);
        tmp1 = BigInteger.valueOf(i2).multiply(tmp1).mod(q);
        Lambdai3 = tmp.multiply(tmp1);
        
        BigInteger reconstructedSecret = si1.multiply(Lambdai1).mod(q);
        reconstructedSecret = reconstructedSecret.add(si2.multiply(Lambdai2).mod(q));
        reconstructedSecret = reconstructedSecret.add(si3.multiply(Lambdai3).mod(q)).mod(q);
        
        //Genero chiave compatibile con ElGamal e la ritorno
        return ElGamal.convertPrivateKey(reconstructedSecret, ElGamal.getP(H.getPublicKey()), ElGamal.getG(H.getPublicKey()));
    }
}

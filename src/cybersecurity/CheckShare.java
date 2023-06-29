
package cybersecurity;

import cybersecurity.Primitives.ShareCypher;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Utils.UtilsFile;
import cybersecurity.Schnorr.SchnorrSig;
import cybersecurity.Schnorr.Schnorr;
import java.math.BigInteger;

public class CheckShare {
    public static void main(String[] args) throws Exception {
        //LOAD THE SHARE FROM THE FILE
        ShareCypher share = UtilsFile.ShareCypherFromFile("miShare.txt"); //Change file name to check other
        
        //LOAD THE KEY
        KeyPairCustom keys = UtilsFile.keyPairFromFile("miKp.txt");
        
        //DECRIPT THE SHARE
        ElGamal el = new ElGamal();
        byte [] cleanshare = el.decode(share.cyphershare, keys.getPrivate());
        byte [] singpt1 = el.decode(share.cyphersignaturept1, keys.getPrivate());
        byte [] singpt2 = el.decode(share.cyphersignaturept2, keys.getPrivate());
        byte [] singpt3 = el.decode(share.cyphersignaturept3, keys.getPrivate());
        
        //CHECK THE SIGNATURE
        SchnorrSig sign = new SchnorrSig(new BigInteger(singpt1),new BigInteger(singpt2), new BigInteger(singpt3));
        PublicKeyCustom H = UtilsFile.PublicKeyFromFile("PublicKey.txt");
        
        BigInteger message= new BigInteger(cleanshare);
        
        if(Schnorr.Verify(sign, H, message.toString())){
            System.out.println("Signature is correct");
        }else
            System.out.println("Signature is not correct");
    }
           
}

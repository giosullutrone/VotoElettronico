package cybersecurity;

import cybersecurity.Primitives.VoteCredential;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Schnorr.Schnorr;
import cybersecurity.Schnorr.SchnorrSig;
import cybersecurity.Utils.UtilsFile;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.crypto.NoSuchPaddingException;

public class VoteCredentialFinder {
    private final ElGamal elGamal;
    
    public VoteCredentialFinder() throws NoSuchAlgorithmException, NoSuchPaddingException {
        elGamal = new ElGamal();
    }
    
    private VoteCredential findVoteCredential(VoteCredential voteCredential, 
                                              KeyPairCustom userKeyPair, PublicKeyCustom PKmi, PublicKeyCustom PKmd) {
        try {
            byte[] rand256 = elGamal.decode(voteCredential.getR(), userKeyPair.getPrivate());
            SchnorrSig sigMI = voteCredential.getSigMI().decode(elGamal, userKeyPair.getPrivate());
            SchnorrSig sigMD = voteCredential.getSigMD().decode(elGamal, userKeyPair.getPrivate());
            
            if (Schnorr.Verify(sigMI, PKmi, new String(rand256)) & 
                Schnorr.Verify(sigMD, PKmd, new String(rand256))) {
                return new VoteCredential(rand256, sigMI, sigMD);
            }
        } catch (Exception ex) {}
        return null;
    }
    
    public VoteCredential findVoteCredential(List<VoteCredential> voteCredentials, 
                                             KeyPairCustom userKeyPair, PublicKeyCustom PKmi, PublicKeyCustom PKmd) {
        for (VoteCredential vc: voteCredentials) {
            VoteCredential correctVoteCredential = findVoteCredential(vc, userKeyPair, PKmi, PKmd);
            
            if (correctVoteCredential != null) {
                return correctVoteCredential;
            }
        }
        return null;
    }
    
    public VoteCredential findVoteCredential(String voteCredentiaPath, List<VoteCredential> voteCredentials, 
                                             KeyPairCustom userKeyPair, PublicKeyCustom PKmi, PublicKeyCustom PKmd) {
        VoteCredential correctVoteCredential = findVoteCredential(voteCredentials, userKeyPair, PKmi, PKmd);

        if (correctVoteCredential != null) {
            UtilsFile.voteCredentialToFile(voteCredentiaPath, correctVoteCredential);
            return correctVoteCredential;
        }
        return null;
    }
    
    public static void main(String[] args) throws Exception {
        VoteCredentialFinder voteCredentialFinder = new VoteCredentialFinder();
        KeyPairCustom userKeyPair = UtilsFile.keyPairFromFile("userKp.txt");
        PublicKeyCustom miPk = UtilsFile.keyPairFromFile("miKp.txt").getPublic();
        PublicKeyCustom mdPk = UtilsFile.keyPairFromFile("mdKp.txt").getPublic();
        List<VoteCredential> voteCredentials = UtilsFile.voteCredentialsFromFile("voteCredentials.txt");
        voteCredentialFinder.findVoteCredential("voteCredential.txt", voteCredentials, userKeyPair, miPk, mdPk);
    }
}

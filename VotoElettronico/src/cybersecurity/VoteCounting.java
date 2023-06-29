package cybersecurity;

import cybersecurity.Primitives.Vote;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Utils.UtilsFile;
import cybersecurity.Utils.Utils;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class VoteCounting {
    public static HashMap<String, Integer> counting(PublicKey PK, PrivateKey SK, List<Vote> votes) throws Exception {
        ElGamal elGamal = new ElGamal();
        HashMap<String, Integer> hashMapSpoglio = new HashMap<>();
        List<Vote> votesSeen = new LinkedList<>();
        
        //4)	Per ciascuna random, manteniamo l’ultima istanza di voto
        for (Vote v: votes) {
            //5)    Consideriamo il voto solo se l'enc di R non è già stata incontrata in precedenza
            boolean alreadyPresent = votesSeen.stream().anyMatch((t) -> {
                return Arrays.equals(v.getVoteCredential().getR(), t.getVoteCredential().getR());
            });
            if (alreadyPresent) {
                continue;
            }
            votesSeen.add(v);
            
            byte[] RDecoded = elGamal.decode(v.getVoteCredential().getR(), PK, SK);
            hashMapSpoglio.put(Utils.toHex(RDecoded), new Integer(elGamal.decode(v.getVote(), PK, SK)[0]));
        }
        return hashMapSpoglio;
    }
    
    public static void main(String args[]) throws Exception {
        List<Vote> votes = UtilsFile.voteFromFile("blockchain.txt");
        if (votes==null) {
            votes = new LinkedList<>();
        }
        //1)	Ricostruiamo la chiave segreta del secret share
        PrivateKey SK = SecretReconstruction.Reconstruct();        
        PublicKeyCustom PKss = UtilsFile.PublicKeyFromFile("PublicKey.txt");
        
        //3)	Creiamo una HashMap che avrà come chiave, il byte array random da 256bit decodificato e il voto associato
        HashMap<String, Integer> result = counting(PKss.getPublicKey(), SK, votes);
        //6)	Salviamo su file l’HashMap ottenuta
        UtilsFile.objectToFile("voteCounting.txt", result);
        System.out.println(result);
    }
}
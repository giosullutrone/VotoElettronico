package cybersecurity;

import cybersecurity.Primitives.VoteCredential;
import cybersecurity.Primitives.BCCredential;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.Schnorr.Schnorr;
import cybersecurity.Schnorr.SchnorrSig;
import cybersecurity.Utils.UtilsFile;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

public class VoteCredentialsGenerator {
    private final SecureRandom random;
    private final ElGamal elGamal;
    
    public VoteCredentialsGenerator() throws Exception {
        random = new SecureRandom();
        elGamal = new ElGamal();
    }
    
    private byte[] getRandom(int securityparameter) {
        byte[] rand = new byte[securityparameter];
        this.random.nextBytes(rand);
        return rand;
    }
    
    public void generate(String bcCredentialsPath, String voteCredentialsPath, KeyPairCustom KPmi, KeyPairCustom KPmd) throws Exception {
        //2)	Otteniamo la lista delle BCCredential sulla nostra blockchain
        List<BCCredential> bcCredentials = UtilsFile.bcCredentialsFromFile(bcCredentialsPath);
        HashMap<String, BCCredential> bcCredentialsHashMap = new HashMap<>();
        
        //3)	Usando una HashMap manteniamo una associazione fra ultimo puk inserito e CF
        for (BCCredential bcCredential: bcCredentials) {
            bcCredentialsHashMap.put(bcCredential.getCf(), bcCredential);
        }
        
        List<VoteCredential> voteCredentials = new LinkedList<VoteCredential>();

        //4)	Per ciascuna entry nell’HashMap, generiamo 256bit di cryptographically strong random bits
        byte[] rand256;
        for (String cf: bcCredentialsHashMap.keySet()) {
            BCCredential bcCredential = bcCredentialsHashMap.get(cf);
            rand256 = getRandom(32);
            
            //5)	Per ciascuna entry generiamo una VoteCredential come presentato nel WP2
            byte[] rConcatRand = elGamal.encode(rand256, bcCredential.getPK());
            
            SchnorrSig sigMI = Schnorr.Sign(KPmi.getPublic(), KPmi.getPrivate(), new String(rand256)).encode(elGamal, bcCredential.getPK());
            SchnorrSig sigMD = Schnorr.Sign(KPmd.getPublic(), KPmd.getPrivate(), new String(rand256)).encode(elGamal, bcCredential.getPK());
            
            //6)	Aggiungiamo la VoteCredential generata alla lista di credenziali di voto
            voteCredentials.add(new VoteCredential(rConcatRand, sigMI, sigMD));
        }
        
        //7)	Mischiamo la lista di credenziali
        Collections.shuffle(voteCredentials);
        //8)	Salviamo su file la lista generata
        UtilsFile.voteCredentialsToFile(voteCredentialsPath, voteCredentials); 
    }
    
    public static void main(String args[]) throws Exception {        
        VoteCredentialsGenerator generator = new VoteCredentialsGenerator();
        
        //1)	Otteniamo le chiavi private di MI e MD
        KeyPairCustom KPmi = UtilsFile.keyPairFromFile("miKp.txt");
        KeyPairCustom KPmd = UtilsFile.keyPairFromFile("mdKp.txt");
        generator.generate("blockchain.txt", "voteCredentials.txt", KPmi, KPmd);
    }
}
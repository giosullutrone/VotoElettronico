package cybersecurity;

import cybersecurity.ElGamal.ElGamal;
import cybersecurity.Utils.UtilsFile;
import java.util.LinkedList;
import java.util.List;

public class minFilesGenerator {
    public static void main(String[] args) throws Exception {        
        // Codice che genera le chiavi
        ElGamal elGamal = new ElGamal();

        UtilsFile.keyPairToFile("miKp.txt", elGamal.generateKeyPair());
        UtilsFile.keyPairToFile("mdKp.txt", elGamal.generateKeyPair());
        UtilsFile.keyPairToFile("mitdKp.txt", elGamal.generateKeyPair());
        UtilsFile.keyPairToFile("mpaKp.txt", elGamal.generateKeyPair());
        
        UtilsFile.objectToFile("blockchain.txt", null);
        
        List<String> abilitati = new LinkedList<>();
        abilitati.add("thisIsACf13.7");
        UtilsFile.objectToFile("abilitati.txt", abilitati);
        List<String> rToClean = new LinkedList<>();
        UtilsFile.objectToFile("rToClean.txt",rToClean);
    }
}

package cybersecurity;

import cybersecurity.Utils.UtilsFile;
import java.util.HashMap;
import java.util.List;

public class VoteCleaning {
    public static HashMap<String, Integer> clean(HashMap<String, Integer> votes, List<String> rToClean) throws Exception {        
        //4)	Per ciascuna entry della hashmap, se la chiave è presente nella lista, rimuoviamo la entry
        for (String v: votes.keySet()) {
            if (rToClean.contains(v)) {
                votes.remove(v);
            }
        }
        return votes;
    }
    
    public static void main(String args[]) throws Exception {
        HashMap<String, Integer> votes = (HashMap<String, Integer>) UtilsFile.objectFromFile("voteCounting.txt");
        
        List<String> rToClean = (List<String>) UtilsFile.objectFromFile("rToClean.txt");
        //1)   Controlliamo la presenza di "R" da rimuovere, in caso contrario possiamo già ritornare i voti
        if (rToClean==null) {
            UtilsFile.objectToFile("voteCleaning.txt", votes);
        }
        
        //2)	Rimuoviamo le R richieste dai voti
        HashMap<String, Integer> result = clean(votes, rToClean);
        //5)	Salviamo su file l’HashMap ottenuta
        UtilsFile.objectToFile("voteCleaning.txt", result);
        System.out.println(result);
    }
}
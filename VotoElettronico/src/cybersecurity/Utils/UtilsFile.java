package cybersecurity.Utils;

import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Primitives.BCCredential;
import cybersecurity.Primitives.ShareCypher;
import cybersecurity.Primitives.Vote;
import cybersecurity.Primitives.VoteCredential;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

public class UtilsFile {
    public static void objectToFile(String filePath, Object object) {
        try (FileOutputStream fos = new FileOutputStream(filePath);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {

            // write object to file
            oos.writeObject(object);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
    
    public static void voteCredentialsToFile(String filePath, List<VoteCredential> voteCredentials) {
        UtilsFile.objectToFile(filePath, voteCredentials);
    }
    
    public static void voteCredentialToFile(String filePath, VoteCredential voteCredential) {
        UtilsFile.objectToFile(filePath, voteCredential);
    }
    
    public static void bcCredentialsToFile(String filePath, List<BCCredential> bcCredentials) {
        UtilsFile.objectToFile(filePath, bcCredentials);
    }
    
    public static void keyPairToFile(String filePath, KeyPairCustom keyPair) {
        objectToFile(filePath, keyPair);
    }
    
    public static void PublicKeyToFile(String filePath, PublicKeyCustom key) {
        objectToFile(filePath, key);
    }
    
    public static void ShareCypherToFile(String filePath, ShareCypher share) {
        objectToFile(filePath, share);
    }
    
    public static void voteToFile(String filePath, Vote vote) {
        UtilsFile.objectToFile(filePath, vote);
    }
    
    public static void votesToFile(String filePath, List<Vote> votes) {
        UtilsFile.objectToFile(filePath, votes);
    }
    
    public static Object objectFromFile(String filePath) {
        try (FileInputStream fis = new FileInputStream(filePath);
            ObjectInputStream ois = new ObjectInputStream(fis)) {

            return ois.readObject();
        } catch (IOException | ClassNotFoundException ex) {
            ex.printStackTrace();
            return null;
        }
    }
    
    public static List<VoteCredential> voteCredentialsFromFile(String filePath) {
        return (List<VoteCredential>) objectFromFile(filePath);
    }
    
    public static List<BCCredential> bcCredentialsFromFile(String filePath) {
        return (List<BCCredential>) objectFromFile(filePath);
    }
    
    public static KeyPairCustom keyPairFromFile(String filePath) {
        return (KeyPairCustom) objectFromFile(filePath);
    }

    public static PublicKeyCustom PublicKeyFromFile(String filePath) {
        return (PublicKeyCustom) objectFromFile(filePath);
    }

    public static VoteCredential voteCredentialFromFile(String filePath) {
        return (VoteCredential) objectFromFile(filePath);
    }
    
    public static ShareCypher ShareCypherFromFile(String filePath) {
        return (ShareCypher) objectFromFile(filePath);
    }
    
    public static List<Vote> voteFromFile(String filePath) {
        return (List<Vote>) objectFromFile(filePath);
    }
}
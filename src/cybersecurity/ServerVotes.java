package cybersecurity;

import cybersecurity.Primitives.Vote;
import cybersecurity.Utils.UtilsFile;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import com.sun.net.ssl.internal.ssl.Provider;
import java.security.Security;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class ServerVotes {
    static void Protocol(Socket sSock) throws Exception {
        InputStream in = sSock.getInputStream(); 
        ObjectInputStream inputstream = new ObjectInputStream(in);
        
        List<Vote> votes = UtilsFile.voteFromFile("blockchain.txt");
        if (votes==null) {
            votes = new LinkedList<>();
        }
        
        //ATTESA DEL VOTO
        Vote vote = (Vote) inputstream.readObject();        
        votes.add(vote);
        
        //4)	Salviamo sulla blockchain i voti ricevuti
        UtilsFile.votesToFile("blockchain.txt", votes);
        sSock.close();
    }

    public static void main(String[] args) throws Exception {
        
        int port = 4000;
        Security.addProvider(new Provider());
        System.setProperty("javax.net.ssl.keyStore","myKeyStore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword","Changeit"); 
        
        //1)	Apriamo la socket
        SSLServerSocketFactory sockfact = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        SSLServerSocket sSock = (SSLServerSocket)sockfact.createServerSocket(port);

        Socket sock = (Socket) sSock.accept();

        //Pulisco blockchain
        UtilsFile.objectToFile("blockchain.txt", null);

        //2)	Attendiamo comunicazione dal client
        Protocol(sock);
    }
}

package cybersecurity;

import cybersecurity.Primitives.VoteCredential;
import cybersecurity.Primitives.Vote;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.PublicKeyCustom;
import cybersecurity.Utils.UtilsFile;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.Security;
import com.sun.net.ssl.internal.ssl.Provider;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class ClientVote {
    enum voteType {
        SCHEDABIANCA,
        CANDIDATO1,
        CANDIDATO2,
        INVALIDATO
    }

    static void Protocol(Socket cSock) throws Exception {
        OutputStream out = cSock.getOutputStream();

        //GENERO IL VOTO
        //Cambiare enum con il voto desiderato
        byte[] votoBase=new byte[] {(byte) voteType.CANDIDATO1.ordinal()};

        //LEGGO LA TRIPLA
        VoteCredential voteCredential = UtilsFile.voteCredentialFromFile("voteCredential.txt");
        //3)	Otteniamo la chiave pubblica di ElGamalCustom del secret share
        PublicKeyCustom PKss = UtilsFile.PublicKeyFromFile("PublicKey.txt");        

        ElGamal elGamal = new ElGamal();
        //4)	Convertiamo la chiave in una compatibile con ElGamal
        VoteCredential cypherCredential = voteCredential.encode(elGamal, PKss.getPublicKey());
        //5)	Creiamo un Vote contenente le VoteCredential e il byte di voto
        Vote cypherVote = new Vote(cypherCredential, elGamal.encode(votoBase, PKss.getPublicKey()));

        //6)	Comunichiamo al server il Vote generato
        ObjectOutputStream outputstream = new ObjectOutputStream(out);
        outputstream.writeObject(cypherVote);

        //FINE CONNESSIONE
        cSock.close();
    }

    public static void main(String[] args) throws Exception {
        int serverPort = 4000;
        String serverName = "localhost";
        Security.addProvider(new Provider());
        System.setProperty("javax.net.ssl.trustStore","myTrustStore.jts");
        System.setProperty("javax.net.ssl.trustStorePassword","Changeit");

        //1)	Apriamo la socket
        SSLSocketFactory sslsockfact = (SSLSocketFactory) SSLSocketFactory.getDefault(); 
        SSLSocket cSock = (SSLSocket)sslsockfact.createSocket(serverName,serverPort); // specify host and port

        Protocol(cSock);
    }

}

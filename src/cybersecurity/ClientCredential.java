package cybersecurity;

import cybersecurity.Primitives.BCCredential;
import cybersecurity.ElGamal.ElGamal;
import cybersecurity.ElGamal.KeyPairCustom;
import cybersecurity.Utils.UtilsFile;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import com.sun.net.ssl.internal.ssl.Provider;
import java.security.Security;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class ClientCredential {
    static void Protocol(Socket cSock) throws Exception {
        OutputStream out = cSock.getOutputStream();
        InputStream in = cSock.getInputStream();
        
        //2)	Generiamo una coppia (PK, SK) di ElGamal
        ObjectOutputStream outputstream = new ObjectOutputStream(out);
        ElGamal elGamal = new ElGamal();
        KeyPairCustom keyPair = elGamal.generateKeyPair();
        String cf="thisIsACf13.7";
        //3)	Salviamo la coppia generata su file
        UtilsFile.keyPairToFile("userKp.txt", keyPair);
        //4)	Creiamo una BCCredential con il CF dell’utente e la PK generata
        BCCredential user = new BCCredential(cf, keyPair.getPublic().getPublicKey());
        
        //5)	Comunichiamo al server la nostra BCCredential
        outputstream.writeObject(user);
	
        // ATTENDI ACK
        ObjectInputStream inputstream = new ObjectInputStream(in);
        String ack = (String)inputstream.readObject();
        
        //6)	Stampiamo a video l’ack ricevuto 
        //      [Semplificazione: non riceviamo la firma delle credenziali ma la sola conferma di inserimento a differenza di come previsto da schema]
        System.out.println(ack);
        
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

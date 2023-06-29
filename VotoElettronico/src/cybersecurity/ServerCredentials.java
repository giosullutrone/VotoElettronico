package cybersecurity;

import cybersecurity.Primitives.BCCredential;
import cybersecurity.Utils.UtilsFile;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.LinkedList;
import java.util.List;
import com.sun.net.ssl.internal.ssl.Provider;
import java.security.Security;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class ServerCredentials {   
    static void Protocol(Socket sSock) throws Exception {
        InputStream in = sSock.getInputStream(); 
        OutputStream out = sSock.getOutputStream();
        
        ObjectInputStream inputstream = new ObjectInputStream(in);
        ObjectOutputStream outputstream = new ObjectOutputStream(out);
        String ack="ok";
        
        //ATTESA CF E PUK
        BCCredential user = (BCCredential)inputstream.readObject();
        
        //3)	In seguito all’arrivo del BCCredential del client, verifichiamo che il CF presentato sia abilitato al voto
        List<String> cflist = (List<String>)UtilsFile.objectFromFile("abilitati.txt");
        boolean found=false;
        for(String c: cflist){
            if(c.equals(user.getCf())){
                found=true;
            }
        }
        if(!found){
            ack="bad cf";
        }
        
        //4)	Verifichiamo che il puk presentato non sia già presente nella blockchain
        List<BCCredential> pucklist = UtilsFile.bcCredentialsFromFile("blockchain.txt");
        if (pucklist==null) {
            pucklist = new LinkedList<>();
        }
        for(BCCredential p: pucklist){
            if(p.getPK().equals(user.getPK())){
                ack="bad puk";
            }
        }

        //INSERISCI BCCredential su blockchain.txt
        if(ack.equals("ok")) {
            pucklist.add(user);
            UtilsFile.bcCredentialsToFile("blockchain.txt", pucklist);
        }
        
        //5)	Rispondiamo al client con un ack di conferma inserimento 
        //      [Semplificazione: torniamo solo una conferma di inserimento e non la firma delle credenziali come previsto da schema]
        outputstream.writeObject(ack);
        //CHIUSRA CONNESSIONE
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
        //2)	Attendiamo comunicazione dal client
        Protocol(sock);
    }
}

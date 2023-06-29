# Voto Elettronico -BALLOTTAGGIO-  Gruppo 7

Progetto voto elettronico esame Algoritmi e protocolli per la sicurezza 2022

### Membri gruppo
* g.mandragora@studenti.unisa.it    0622701875
* d.picone6@studenti.unisa.it       0622701750
* g.sullutrone2@studenti.unisa.it   0622701751
* f.tirino@studenti.unisa.it        0622701745

## Funzioni implementate

* minFilesGenerator.java : Questa classe inizializza la votazione creando tutti i file necessari per inizializzare, quali:
  * blockchain.txt : file che simula la blockchain;
  * m***Kp.txt : file che contiene la coppia chiave pubblica e segreta del ministero specificato dal nome;
  * abilitati.txt : file che contiene abilitati alla votazione, per testing contiene solo un codice fiscale di prova;
  * rToClean.txt : file che conterrà le r da rimuovere dalla blockchain;
  * miKpSign.txt : file che contiene la coppia di chiavi del ministero degli interni per la firma;
  * mdKpSign.txt : file che contiene la coppia di chiavi del ministero della difesa per la firma;
* SecretSharing.java : Questa classe si occupa di: generare una coppia chiave pubblica e privata di elgamal; dividere il segreto della chiave privata tra i ministeri cifrandola con la loro chiave pubblica; inoltre, genera una firma basata sulla chiave privata anch'essa cifrata;
* CheckShare.java : Questa classe permette di controllare la share e la firma per il ministero specificato all'interno della classe;
* Client/ServerCredential/s.java : Queste due classi servono per simulare la comunicazione tra il client e il server che carica le informazioni sulla blockchain (dato il suo funzionamento va eseguito prima il server e poi il client). È possibile, inoltre, provare a inserire dati errati o altri dati modificandoli nel codice del client. Ovviamente sono stai implementati controlli semplici su quello che è stato inserito;
* VoteCredentialGenerator.java : Questa classe prende le coppie di firme generate precendentemente, il file contentente la blockchain simulata e restituisce le credenziali (tripla) per ogni utente nella blockchain cifrata usando la chiave pubblica specificata;
* VoteCredentialFinder.java : Questa classe permette all' utente di trovare la sua credenziale all' interno del file di credenziali controllando le firme dopo aver decifrato con la sua chiave segreta;
* Client/ServerVote.java : Queste due classi simulano l'inserimento del voto nella blockchain, dato che non è stato possibile implementare la prova zeroknowledge non viene fatto alcun controllo su quello che viene inviato dal client, dunque semplicemente il voto e le credenziali vengono scritte sulla blockchain;
* VoteCounting.java : Questa classe si occupa di eseguire lo spoglio dei voti resituendo le ultime iterazioni per ogni tripla con il voto associato;
* VoteCleaning.java : Questa classe si occupa di rimuovere eventuali credenziali che hanno avuto problemi e hanno ricorso a justice prendendole dal file rToClean;

## Come eseguire

Per una corretta esecuzione dobbiamo seguire il seguente ordine:

1. minFilesGenerator.java
2. SecretSharing.java
   * Dopo aver eseguito SecretSharng.java possiamo controllare con CheckShare.java le firme delle share
3. ServerCredentials.java
4. ClientCredential.java
5. VoteCredentialGenerator.java 
6. VoteCredentialFinder.java
7. ServerVote.java
8. ClientVote.java
9. VoteCounting.java
10. VoteCleaning.java
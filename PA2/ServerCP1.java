import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.*;

public class ServerCP1 {
	
	public static void main(String[] args) {

		try{
			//Creating Server certificate
			InputStream fisServer = new FileInputStream("keysAndCert/certificate_1004271.crt");
			CertificateFactory cfServer = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert =(X509Certificate)cfServer.generateCertificate(fisServer);

			//Extract public key from Server certificate
			PublicKey serverPublicKey = serverCert.getPublicKey();

			//Get server's private key
			PrivateKey serverPrivateKey = PrivateKeyReader.get("keysAndCert/private_key.der");
		
		

			int port = 4321;
			if (args.length > 0) port = Integer.parseInt(args[0]);

			ServerSocket welcomeSocket = null;
			Socket connectionSocket = null;
			DataOutputStream toClient = null;
			DataInputStream fromClient = null;

			FileOutputStream fileOutputStream = null;
			BufferedOutputStream bufferedFileOutputStream = null;

		
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());



			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				//if asked to prove identity
				if (packetType == 88) {

					System.out.println("Client is asking for proof of identity");
					String proofMessage = fromClient.readUTF();

					//encrypt the message
					String encryptedMessage = Base64Class.encode(RSA.encrypt(proofMessage.getBytes(), serverPrivateKey));

					//send encrypted message to Client
					toClient.writeUTF(encryptedMessage);
				}
				//if asked for server cert
				if (packetType == 888) {
					System.out.println("Client is asking for certification");
					String encryptedServerCert = Base64Class.encode(serverCert.getEncoded());

					//send encrypted Server certificate to Client
					toClient.writeUTF(encryptedServerCert);
				}
				//if error is present
				if (packetType == 404) {
					System.out.println("Error 404");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
			} 
			
				
				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					int numBytesFilename = fromClient.readInt();
					
					byte [] filename = new byte[numBytesFilename];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytesFilename);

					byte[] decryptedFilename = RSA.decrypt(filename, serverPrivateKey);

					fileOutputStream = new FileOutputStream("recv_"+new String(decryptedFilename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					int numBytesFile = fromClient.readInt();
					byte [] block = new byte[numBytesFile];
					fromClient.readFully(block, 0, numBytesFile);

					byte[] decryptedFile = RSA.decrypt(block, serverPrivateKey);

					if (numBytes> 0)
						bufferedFileOutputStream.write(decryptedFile, 0, numBytes);

					if (numBytes < 117) {

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						
					}
				}

			}
		
	}
	catch(Exception e) {
		e.printStackTrace();
	}

	}

}
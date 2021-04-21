import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
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
import java.io.FileNotFoundException;
import java.io.IOException;

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

			FileInputStream fileInputStream = null;
			BufferedInputStream bufferedFileInputStream = null;

		
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

				//download
				if (packetType == 3) {
					long timeStarted = System.nanoTime();
					try{
						System.out.println("download request...");

						int numBytes = fromClient.readInt();
						int numBytesFilename = fromClient.readInt();
						
						byte [] filename = new byte[numBytesFilename];
						// Must use read fully!
						// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
						fromClient.readFully(filename, 0, numBytesFilename);

						byte[] decryptedFilename = RSA.decrypt(filename, serverPrivateKey);

						fileInputStream = new FileInputStream("Server/"+new String(decryptedFilename, 0, numBytes));
						System.out.println("download "+new String(decryptedFilename, 0, numBytes) + " requested");
						bufferedFileInputStream = new BufferedInputStream(fileInputStream);
						toClient.writeInt(3);

						byte [] fromFileBuffer = new byte[117];

						for (boolean fileEnded = false; !fileEnded;) {

		
							//bufferedFileInputStream reads bytes from byte-input stream into byte array, fromFileBuffer
							numBytes = bufferedFileInputStream.read(fromFileBuffer);
							fileEnded = numBytes < 117;

							toClient.writeInt(4);
							//send original bytes of file
							toClient.writeInt(numBytes);
							
							byte[] encryptedFile = RSA.encrypt(fromFileBuffer, serverPrivateKey);

							int numBytesFile = encryptedFile.length;

							toClient.writeInt(numBytesFile);
							toClient.write(encryptedFile);
							toClient.flush();
						}

						long timeTaken = System.nanoTime() - timeStarted;
						System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
						toClient.writeInt(5);
					}
			
					catch(IOException e) {
						System.out.println("File does not exist. Please key in a valid file name");
						toClient.writeInt(404);
					}
				}


				
				else if(packetType == 4){

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

					fileOutputStream = new FileOutputStream("Server/recv_"+new String(decryptedFilename, 0, numBytes));
					System.out.println("recv_"+new String(decryptedFilename, 0, numBytes) + " received!");
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

				// exit
				if(packetType == 8){
					System.out.println("Closing Connection...");
					fromClient.close();
					toClient.close();
					connectionSocket.close();
					System.out.println("Exiting...");
				}

			}
		
	}
	catch(Exception e) {
		e.printStackTrace();
	}

	}

}

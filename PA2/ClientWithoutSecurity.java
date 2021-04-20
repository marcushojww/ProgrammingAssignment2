import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientWithoutSecurity {


	public static void main(String[] args) {

		// String filename = "100.txt";
    	// if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	// if (args.length > 1) filename = args[1];

    	int port = 4321;
    	// if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			//Creating CA certificate
			InputStream fis = new FileInputStream("keysAndCert/cacsertificate.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);

			//Extract public key from CA certificate
			PublicKey caPublicKey = CAcert.getPublicKey();
		

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			//Commence authentication of server
			//ask server to prove its identity
			toServer.writeInt(88);
			String proofMessage = "Hello Server, please prove your identity";
			toServer.writeUTF(proofMessage);

			//request for certificate
			String encryptedMsg = fromServer.readUTF();
			toServer.writeInt(888);
			System.out.println("Receiving certificate from server for authentication...");
			
			//retrieve Server certificate String
			String serverCertString = fromServer.readUTF();
			byte[] serverCertByte = Base64Class.decode(serverCertString);

			//create Server certificate
			InputStream inputStream = new ByteArrayInputStream(serverCertByte);
			CertificateFactory cf1 = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert =(X509Certificate)cf1.generateCertificate(inputStream);
			
			//get Server public key
			PublicKey serverPublicKey = serverCert.getPublicKey();

			//check validity and verify
			try{
				CAcert.checkValidity();
				serverCert.verify(caPublicKey);
			}
			catch(Exception e){
				e.printStackTrace();
				System.out.println("Invalid Certificate and Verification. Closing connection...");
				toServer.writeInt(404);
				clientSocket.close();
				
			}
			//decrypt encrypted message with Server's public key
			byte[] decryptedByte = RSA.decrypt(Base64Class.decode(encryptedMsg), serverPublicKey);
			
			//close connection if decrypted message != proof message 
			if (!Arrays.equals(decryptedByte, proofMessage.getBytes())) {
				System.out.println("Messages do not match. Closing connection...");
				toServer.writeInt(404);
				clientSocket.close();
			}

			System.out.println("Server succesfully authenticated.");

			// System.out.println("Sending file...");

			for (int i = 0; i < args.length; i++) {

				//access filename from argument
				String filename = args[i];

				//encrypt filename
				byte[] encryptedFilename = RSA.encrypt(filename.getBytes(), serverPublicKey);
				int numBytesFilename = encryptedFilename.length;
				// Send the filename
				toServer.writeInt(0);
				//original bytes of filename
				toServer.writeInt(filename.getBytes().length);
				//send length of filename byte array so client can use length
				//to create a byte array of suitable length to store byte from filename
				//when readFully
				toServer.writeInt(numBytesFilename);
				//sending content in bytes
				toServer.write(encryptedFilename);
				//toServer.flush();

				// Open the file
				//FileInputSteam obtains input bytes from a file
				//it is used for reading byte-orientated data
				fileInputStream = new FileInputStream(filename);

				//BufferedInputStream is used to read information from a stream
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);

				byte [] fromFileBuffer = new byte[117];

				// Send the file
				for (boolean fileEnded = false; !fileEnded;) {

					//bufferedFileInputStream reads bytes from byte-input stream into byte array, fromFileBuffer
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
					fileEnded = numBytes < 117;

					toServer.writeInt(1);
					//send original bytes of file
					toServer.writeInt(numBytes);
					
					byte[] encryptedFile = RSA.encrypt(fromFileBuffer, serverPublicKey);

					int numBytesFile = encryptedFile.length;

					toServer.writeInt(numBytesFile);
					toServer.write(encryptedFile);
					toServer.flush();
				}

				if (i == args.length - 1) {

					toServer.writeInt(8);

				}
			

			}

			System.out.println("Closing connection...");

			bufferedFileInputStream.close();
			fileInputStream.close();
			clientSocket.close();

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}


	
}

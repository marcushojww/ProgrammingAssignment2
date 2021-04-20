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

		String filename = "100.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	if (args.length > 1) filename = args[1];

    	int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

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
				System.out.println("Closing connection...");
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

			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
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
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;

				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();

			System.out.println("Closing connection...");

			clientSocket.close();

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}


	
}

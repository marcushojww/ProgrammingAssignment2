import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ClientCP2 {


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
		
		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		

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
            
            //Generate AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey aesKey = keyGen.generateKey();

            System.out.println("AES key generated successfully.");

            //Share AES key
            toServer.writeInt(8888);
            //Encrypt AES key
            byte[] aesKeyByte = RSA.encrypt(aesKey.getEncoded(), serverPublicKey);
            //Get encrypted string of AES key
            String aesKeyString = Base64Class.encode(aesKeyByte);
            //Send aesKeyString to server
            toServer.writeUTF(aesKeyString);



			while (true) {

				Scanner in = new Scanner(System.in);
				System.out.println("> ");
				String input = in.nextLine();
				String [] inputSplit = input.split(" ");

				if (inputSplit[0].equals("exit")) {

					toServer.writeInt(8);
					System.out.println("Closing connection...");
					if (bufferedFileInputStream != null) bufferedFileInputStream.close();
					if(fileInputStream != null) fileInputStream.close();
					clientSocket.close();
					break;

				}
				else if (inputSplit[0].equals("upload")) {

					if (inputSplit.length == 1){
						System.out.println("Please enter a filename");
					}
					else
					{
						try {
							long timeStarted = System.nanoTime();

							for (int i = 1; i < inputSplit.length; i++) {

								String filename = inputSplit[i];

								// Open the file
								//FileInputSteam obtains input bytes from a file
								//it is used for reading byte-orientated data
								fileInputStream = new FileInputStream("Client/" + filename);

								//BufferedInputStream is used to read information from a stream
								bufferedFileInputStream = new BufferedInputStream(fileInputStream);
	
								// Send the filename
								toServer.writeInt(0);
								//original bytes of filename
								toServer.writeInt(filename.getBytes().length);
								
								byte[] encryptedFilename = AES.encrypt(filename.getBytes(), aesKey);
								toServer.writeInt(encryptedFilename.length);
								toServer.write(encryptedFilename);
								
								//toServer.flush();
	
								byte [] fromFileBuffer = new byte[117];
	
								// Send the file
								for (boolean fileEnded = false; !fileEnded;) {
	
									//bufferedFileInputStream reads bytes from byte-input stream into byte array, fromFileBuffer
									numBytes = bufferedFileInputStream.read(fromFileBuffer);
									fileEnded = numBytes < 117;
	
									toServer.writeInt(1);
									//send original bytes of file
									toServer.writeInt(numBytes);
									
									byte[] encryptedFile = AES.encrypt(fromFileBuffer, aesKey);
                                    
									int numBytesFile = encryptedFile.length;
	
									toServer.writeInt(numBytesFile);
									toServer.write(encryptedFile);
									toServer.flush();
								}
							}
	
							long timeTaken = System.nanoTime() - timeStarted;
							System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
						}
						catch(IOException e) {
							System.out.println("File does not exist. Please key in a valid file name");
						}
						
					}


				}

				else if (inputSplit[0].equals("download")) {

					if (inputSplit.length == 1){
						System.out.println("Please enter a filename");
					}
					else
					{
						for (int i = 1; i < inputSplit.length; i++) {

							String filename = inputSplit[i];
							
							byte[] encryptedFilename = AES.encrypt(filename.getBytes(), aesKey);
							int numBytesFilename = encryptedFilename.length;
							
							toServer.writeInt(3);
							//original bytes of filename
							toServer.writeInt(filename.getBytes().length);
							//send length of filename byte array so client can use length
							//to create a byte array of suitable length to store byte from filename
							//when readFully
							toServer.writeInt(numBytesFilename);
							//sending content in bytes
							toServer.write(encryptedFilename);

							// Open the file
							//FileInputSteam obtains input bytes from a file
							//it is used for reading byte-orientated data

							
							int packetType = 0;
							long timeStarted = System.nanoTime();
							
							do {
								packetType = fromServer.readInt();
								
								if(packetType == 3){
									fileOutputStream = new FileOutputStream("Client/downloaded_" + filename);

									//BufferedInputStream is used to read information from a stream
									bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
								}

								else if(packetType == 4){

									numBytes = fromServer.readInt();

									int numBytesFile = fromServer.readInt();
									
									byte [] block = new byte[numBytesFile];
									fromServer.readFully(block, 0, numBytesFile);

									byte[] decryptedFile = AES.decrypt(block, aesKey);

									if (numBytes> 0)
									bufferedFileOutputStream.write(decryptedFile, 0, numBytes);

									if (numBytes < 117) {
										System.out.println("Finished");

										if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
										if (bufferedFileOutputStream != null) fileOutputStream.close();
										
									}
								}
								else if(packetType == 404){
									System.out.println("File does not exist! Please key in a valid file name");
									break;
								}
								
							} while (packetType != 5);

							long timeTaken = System.nanoTime() - timeStarted;
							System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
							
						}
					}


				}
				else {
					System.out.println("Please key a valid input");
				}
				

			}

		} catch (Exception e) {e.printStackTrace();}
	}


	
}


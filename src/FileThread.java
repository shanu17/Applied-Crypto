/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.spec.SecretKeySpec;

public class FileThread extends Thread
{
	private final Socket socket;
	private SecretKey sym_K = null;
	private FileServer my_fs;
	private UserToken VerifyToken;
	private static final BigInteger p_2056 = new BigInteger(1,Hex.decode("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF"));

	private static final BigInteger g_2056 = BigInteger.valueOf(2);

	public FileThread(Socket _socket, FileServer _fs)
	{
		socket = _socket;
		my_fs = _fs;
	}

	public void run()
	{
		boolean proceed = true;
		Security.addProvider(new BouncyCastleProvider());
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler for Diffie Hellman Exchange
				if(e.getMessage().equals("DH"))
				{
					if (e.getObjContents().size() < 1)
						response = new Envelope("FAIL-BADCONTENTS");
					else
					{
						// Define Diffie Hellman Parameters
						DHParameterSpec dhParams = new DHParameterSpec(p_2056, g_2056);
				    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

						//Initialize Diffie Hellman Exchange
						keyGen.initialize(dhParams, new SecureRandom());
						KeyAgreement serverDH = KeyAgreement.getInstance("DH", "BC");
				    KeyPair serverPair = keyGen.generateKeyPair();

						try
						{
							// Generate sym_K
							serverDH.init(serverPair.getPrivate());

							// Decrypt public key with fileServer's private key
							Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
							cipher.init(Cipher.DECRYPT_MODE, my_fs.privateKey);

							//PublicKey clientDHPub = (PublicKey) e.getObjContents().get(0);
							ByteArrayInputStream bis = new ByteArrayInputStream((byte[]) e.getObjContents().get(0));
							ObjectInput in = new ObjectInputStream(bis);
							PublicKey clientDHPub = (PublicKey)in.readObject();

							serverDH.doPhase(clientDHPub, true);
							MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");
							byte[] encodedKey = hash.digest(serverDH.generateSecret());
							sym_K = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");

							response = new Envelope("OK");
							response.addObject(serverPair.getPublic());
						}
						catch (Exception ex)
						{
							ex.printStackTrace();
							response = new Envelope("FAIL");
						}
						output.writeObject(response);
					}
				}

				if(e.getMessage().equals("TOKEN_VERIFY"))
				{
					response = new Envelope("FAIL-BADCONTENTS");
					if(e.getObjContents().size()<2)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						byte[] iv = (byte[]) e.getObjContents().get(0);
						Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
						ByteArrayInputStream byteStream = new ByteArrayInputStream(cipher.doFinal((byte[])e.getObjContents().get(0)));
	 		    		ObjectInputStream objStream = new ObjectInputStream(byteStream);
	 					UserToken tokenT = (UserToken) objStream.readObject(); //Extract token
	 					long time_token = tokenT.getTime();
	 					Date date= new Date();
					    long time = date.getTime();
					    RSAPublicKey pub_token = (RSAPublicKey) tokenT.getPublicKey();
	 					if(time-time_token > 20000 && pub_token != my_fs.publicKey)
	 					{
	 						response = new Envelope("FAIL-BADCONTENTS");
	 					}
	 					else
	 					{
	 						this.VerifyToken=tokenT;
	 						response = new Envelope("OK");
	 					}
					}
					output.writeObject(response);
				}
				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
					if (e.getObjContents().size() < 1)
						response = new Envelope("FAIL-BADCONTENTS");
					else
					{
						if(e.getObjContents().get(0)==null)
							response = new Envelope("FAIL-BADTOKEN");
						else
						{


							Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
							byte[] iv = (byte[]) e.getObjContents().get(1);
		 				 	cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));

		 					ByteArrayInputStream byteStream = new ByteArrayInputStream(cipher.doFinal((byte[])e.getObjContents().get(0)));
		 		    		ObjectInputStream objStream = new ObjectInputStream(byteStream);
		 					UserToken tokenT = (UserToken) objStream.readObject(); //Extract token
							List<ShareFile> Files = FileServer.fileList.getFiles(); // Get all the files that are in the file server
							List<String> UserFiles = new ArrayList<String>(); // Create an list of arrays that can store all the user files
							List<String> groups = tokenT.getGroups(); // get the groups which the user belongs to

								for (ShareFile sf: Files) {
									if (groups.contains(sf.getGroup())){ // If our token contains all the groups or if your the owner of the group
										UserFiles.add(sf.getPath());
									}
									System.out.println("ahha");
								}

								cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
								ByteArrayOutputStream baos = new ByteArrayOutputStream();
								DataOutputStream out = new DataOutputStream(baos);
								for (String element : UserFiles) {
								    out.writeUTF(element);
								}
								byte[] uf_enc = baos.toByteArray();

							if(this.VerifyToken!=tokenT)
							{
								response = new Envelope ("FAIL-BADCONTENTS");
								output.writeObject(response);
							}
							else
							{
								response = new Envelope("OK");
								response.addObject(uf_enc);
								output.writeObject(response);
							}
						}
					}
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {

							//Decrypt
							Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			 			 	byte[] iv = (byte[]) e.getObjContents().get(3);
			 			 	cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));

							String remotePath = new String(cipher.doFinal((byte[])e.getObjContents().get(0)));
							String group = new String(cipher.doFinal((byte[])e.getObjContents().get(1)));

		 					ByteArrayInputStream byteStream = new ByteArrayInputStream(cipher.doFinal((byte[])e.getObjContents().get(2)));
		 		    		ObjectInputStream objStream = new ObjectInputStream(byteStream);
		 						UserToken tokenT = (UserToken) objStream.readObject(); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!tokenT.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);


								// Decrypt

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])cipher.doFinal((byte[])e.getObjContents().get(0)), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(tokenT.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
					output.reset();
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					byte[] iv = (byte[]) e.getObjContents().get(2);
					cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));


					String remotePath = new String(cipher.doFinal((byte[])e.getObjContents().get(0)));
					ByteArrayInputStream byteStream = new ByteArrayInputStream(cipher.doFinal((byte[])e.getObjContents().get(1)));
 		    		ObjectInputStream objStream = new ObjectInputStream(byteStream);
 						UserToken tokenT = (UserToken) objStream.readObject(); //Extract token
					//UserToken t = (UserToken)cipher.doFinal((byte[])e.getObjContents().get(1));
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!tokenT.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", tokenT.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}

								//Encrypt buf -> buf_enc
								cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
								byte[] buf_enc = cipher.doFinal(buf);

								e.addObject(buf_enc);
								e.addObject(new Integer(n));
								e.addObject(iv);

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{
								if(this.VerifyToken!=tokenT)
								{
									response = new Envelope ("FAIL-BADCONTENTS");
									output.writeObject(response);
								}
								else
								{
									e = new Envelope("EOF");
									output.writeObject(e);
								}
								

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							//e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					byte[] iv = (byte[]) e.getObjContents().get(2);
					cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
					ByteArrayInputStream byteStream = new ByteArrayInputStream(cipher.doFinal((byte[])e.getObjContents().get(1)));
 		    		ObjectInputStream objStream = new ObjectInputStream(byteStream);
 						UserToken tokenT = (UserToken) objStream.readObject(); //Extract token
					//UserToken t = (UserToken) cipher.doFinal((byte[])e.getObjContents().get(1));
					String remotePath = new String (cipher.doFinal((byte[])e.getObjContents().get(0)));

					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!tokenT.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", tokenT.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							//e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					if(this.VerifyToken!=tokenT)
					{
						response = new Envelope ("FAIL-BADCONTENTS");
						output.writeObject(response);
					}
					else
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			//e.printStackTrace(System.err);
		}
	}

}

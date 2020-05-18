/* FileClient provides all the client functionality regarding the file server */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.UnsupportedEncodingException;

import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.encoders.Hex;
//import org.bouncycastle.x509.;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;

import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.*;


public class FileClient extends Client implements FileClientInterface{

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
	private final SecureRandom rand = new SecureRandom();
	private SecretKey sym_K = null;
	private byte[] iv = new byte[16];
	RSAPublicKey filePub;


	public boolean clientDHExchange() throws IOException{
		Security.addProvider(new BouncyCastleProvider());
		
		try 
		{
			InputStream inStream = new FileInputStream("fileKeystore.jks");
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(inStream,"password".toCharArray());
			X509Certificate cert=(X509Certificate) ks.getCertificate("selfsigned");
			cert.checkValidity();
			filePub = (RSAPublicKey) cert.getPublicKey();
			KeyPair clientPair;
			KeyAgreement clientDH;
			Envelope response;
			DHParameterSpec dhParams = new DHParameterSpec(p_2056, g_2056);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

			//Initialize Diffie Hellman Exchange
			keyGen.initialize(dhParams, rand);
			clientDH = KeyAgreement.getInstance("DH", "BC");
			clientPair = keyGen.generateKeyPair();

			Envelope msg = new Envelope("DH");
			Envelope msg2 = new Envelope("DH1");
			// Encrypt public key with fileServer's public key
			Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, filePub);

			// change token to bit stream
			ByteArrayOutputStream byteStream_k = new ByteArrayOutputStream();
			ObjectOutputStream oos_k = new ObjectOutputStream(byteStream_k);
			oos_k.writeObject((clientPair.getPublic()));
			byte[] keyBytes = byteStream_k.toByteArray();

			byte[] ciphertext = cipher.doFinal(keyBytes);
			// Send public key to File Server
			msg.addObject(clientPair.getPublic());
			output.writeObject(msg);
			response = (Envelope)input.readObject();
			// Upon reponse, generate sym_K
			clientDH.init(clientPair.getPrivate());
			clientDH.doPhase((PublicKey)response.getObjContents().get(0), true);
			MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");
			
			ByteArrayInputStream byteStream = new ByteArrayInputStream(hash.digest(clientDH.generateSecret()));
			ObjectInputStream objStream = new ObjectInputStream(byteStream);
			SecretKey keyT = (SecretKey) objStream.readObject();
			this.sym_K = keyT;
		}catch(Exception e)
		{
			e.printStackTrace();
			return false;
		}
		
		// Define Diffie Hellman Parameters
		return true;
	}

	public boolean send_token(UserToken token)
	{
		try
		{
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(byteStream);
			oos.writeObject(token);
			byte[] byteToken = byteStream.toByteArray();
			Envelope env = new Envelope("TOKEN_VERIFY");
			Cipher send_tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			rand.nextBytes(iv);
			send_tok.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
			byte[] t_enc = send_tok.doFinal(byteToken);
			env.addObject(send_tok.getIV());
			env.addObject(t_enc);
			output.writeObject(env);
			env = (Envelope)input.readObject();
			if(env.getMessage()!="OK")
			{
				return false;
			}
			else
				return true;
		}catch(Exception e)
		{
			e.printStackTrace();
			return false;
		}
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		try {
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(byteStream);
			oos.writeObject(token);
			byte[] byteToken = byteStream.toByteArray();
			Envelope env = new Envelope("DELETEF"); //Success
			//Encrypt
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			rand.nextBytes(iv);
			cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
			byte[] t_enc = cipher.doFinal(byteToken);
			byte[] rp_enc = cipher.doFinal(remotePath.getBytes("UTF-8"));
			env.addObject(rp_enc);
			env.addObject(t_enc);	
			env.addObject(cipher.getIV());
			output.writeObject(env);
		    env = (Envelope)input.readObject();

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
			
		}catch(Exception e)
		{
			e.printStackTrace();
			return false;
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}

				File file = new File(destFile);
				try 
				{
					if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);

					    Envelope env = new Envelope("DOWNLOADF"); //Success

							Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
							rand.nextBytes(iv);
							cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));

							// change token to bit stream
							ByteArrayOutputStream byteStream_t = new ByteArrayOutputStream();
							ObjectOutputStream oos_t = new ObjectOutputStream(byteStream_t);
							oos_t.writeObject(token);
							byte[] byteToken = byteStream_t.toByteArray();

							byte[] t_enc = cipher.doFinal(byteToken);
							byte[] sf_enc = cipher.doFinal(sourceFile.getBytes("UTF-8"));
					    env.addObject(sf_enc);
					    env.addObject(t_enc);
							env.addObject(cipher.getIV());

					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env);

					    env = (Envelope)input.readObject();





						cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

						// change any object to bit stream
						ByteArrayOutputStream byteStream_ = new ByteArrayOutputStream();
						ObjectOutputStream oos_ = new ObjectOutputStream(byteStream_);
						oos_.writeObject(env.getObjContents().get(2));
						byte[] iv = byteStream_.toByteArray();

						cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
						while (env.getMessage().compareTo("CHUNK")==0) {

								ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
								ObjectOutputStream oos = new ObjectOutputStream(byteStream);
								oos.writeObject((env.getObjContents().get(0)));
								byte[] envBytes = byteStream.toByteArray();

							  cipher.doFinal(envBytes, 0, (Integer)env.getObjContents().get(1));
								fos.write(envBytes);
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env);
								env = (Envelope)input.readObject();
						}
						fos.close();

					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(env);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;
						}
				    }

				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
					
				}catch(Exception e)
				{
					e.printStackTrace();
					return false;
				}
				 return true;
	}

	public static List<String> bytesToStringList(byte[] bytes) throws IOException{
	      List<String> lines = new ArrayList<String>();

	      if (bytes == null) {
	        return lines;
	      }

	      BufferedReader r = null;

	      try {
	        r = new BufferedReader(
	                new InputStreamReader(new ByteArrayInputStream(bytes),"UTF-8"));
	      } catch (UnsupportedEncodingException e) {
	        // If UTF-8 is not supported we are in big trouble.
	        throw new RuntimeException(e);
	      }

	      try {
	        try {
	          for (String line = r.readLine(); line != null; line = r.readLine()) {
	            lines.add(line);
	          }
	        } finally {
	          r.close();
	        }
	      } catch (IOException e) {
	        // I can't think of a reason we'd get here.
	        throw new RuntimeException(e);
	      }

	      return lines;
	    }
	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 // change token to bit stream
			 ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			 ObjectOutputStream oos = new ObjectOutputStream(byteStream);
			 oos.writeObject(token);
			 byte[] byteToken = byteStream.toByteArray();

			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");


			 Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			 rand.nextBytes(iv);
			 cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
			 byte[] t_enc = cipher.doFinal(byteToken);
			 message.addObject(t_enc);
			 message.addObject(cipher.getIV());
			 message.addObject(t_enc); //Add requester's token
			 output.writeObject(message);



			 e = (Envelope)input.readObject();
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				 // change token to bit stream
				ByteArrayOutputStream byteStream_tr = new ByteArrayOutputStream();
				ObjectOutputStream oos_tr = new ObjectOutputStream(byteStream_tr);
				oos_tr.writeObject(e.getObjContents().get(1));
				byte[] ivBytes = byteStream_tr.toByteArray();
				iv = ivBytes;
				cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));

				ByteArrayOutputStream byteStream_str = new ByteArrayOutputStream();
				ObjectOutputStream oos_str = new ObjectOutputStream(byteStream_str);
				oos_str.writeObject(e.getObjContents().get(0));
				byte[] stringListBytes = byteStream_str.toByteArray();
				cipher.doFinal(stringListBytes);
				return bytesToStringList(stringListBytes);
			 }

			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return null;
			}
	}


	public boolean upload(String sourceFile, String destFile, String group,UserToken token){

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {

			 // change token to bit stream
		 	 ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		 	 ObjectOutputStream oos = new ObjectOutputStream(byteStream);
		 	 oos.writeObject(token);
		 	 byte[] byteToken = byteStream.toByteArray();

			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");

			 //TODO: Encrypt
			 Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			 rand.nextBytes(iv);
			 cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
			 byte[] dest_enc = cipher.doFinal(destFile.getBytes("UTF-8"));
			 byte[] g_enc = cipher.doFinal(group.getBytes("UTF-8"));
			 byte[] t_enc = cipher.doFinal(byteToken);

			 message.addObject(dest_enc);
			 message.addObject(g_enc);
			 message.addObject(t_enc); //Add requester's token
			 env.addObject(cipher.getIV());
			 output.writeObject(message);


			 FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }


			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					// ENCRYPT
					byte[] buf_enc = cipher.doFinal(buf);
					message.addObject(buf_enc);
					message.addObject(new Integer(n));

					output.writeObject(message);


					env = (Envelope)input.readObject();


			 }
			 while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				output.writeObject(message);

				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
					fis.reset();
				}
				else {

					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				//e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

}

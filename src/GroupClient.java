/* Implements the GroupClient Interface */

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class GroupClient extends Client implements GroupClientInterface {

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
	private PublicKey groupServerPublicKey;
	private byte[] signedHash;
	private byte[] tokensig;
	private HashMap<String, ArrayList<SecretKey>> groupKeys;
	//private GroupServerPublicKey;


	public static List<String> bytesToStringList(byte[] bytes) {
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

	public void getGroupKeys(UserToken t){
		// Request group Keys
		Envelope request = new Envelope("GETKEYS");
		Cipher cipher;

		try{
			cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, sym_K);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(t);
			byte[] byteToken = bos.toByteArray();

			byte[] t_enc = cipher.doFinal(byteToken);
			request.addObject(cipher.getIV());
			request.addObject(t_enc);

			output.writeObject(request);

			Envelope resp = (Envelope)input.readObject();

			// Handle and Store Keys from response
			byte[] iv = (byte[])resp.getObjContents().get(0);
			cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
			byte[] map_raw = cipher.doFinal((byte[])resp.getObjContents().get(1));

			ByteArrayInputStream bis = new ByteArrayInputStream(map_raw);
			ObjectInputStream ois = new ObjectInputStream(bis);
			groupKeys = (HashMap<String, ArrayList<SecretKey>>) ois.readObject();
		} catch (Exception e){
			e.printStackTrace();
		}
	}

	public void addNewGroupKey(String groupName, UserToken t){
		// Generate AESKey
		SecretKey key = null;
		try{
			KeyGenerator keyGen = KeyGenerator.getInstance("AES/CTR/NoPadding");
			keyGen.init(256);
			key = keyGen.generateKey();
		} catch (Exception e){
			e.printStackTrace();
		}

		// Add Key to groupKeys
		ArrayList<SecretKey> entry = new ArrayList<SecretKey>();
		entry.add(key);
		groupKeys.put(groupName, entry);

		// Send Key to GroupServer
		Envelope msg = new Envelope("ADDKEY");
		Cipher cipher;
		try{
			cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, sym_K);

			ByteArrayOutputStream bs = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(bs);
			os.writeObject(t);
			byte[] byteToken = bs.toByteArray();
			bs = new ByteArrayOutputStream();
			os = new ObjectOutputStream(bs);
			os.writeObject(key);
			byte[] byteKey = bs.toByteArray();

			byte[] t_enc = cipher.doFinal(byteToken);
			byte[] key_enc = cipher.doFinal(byteKey);
			msg.addObject(cipher.getIV()); 												// 0 => iv
			msg.addObject(t_enc); 																// 1 => token
			msg.addObject(cipher.doFinal(groupName.getBytes())); 	// 2 => groupname
			msg.addObject(key_enc); 															// 3 => key
		} catch (Exception e){
			e.printStackTrace();
		}
	}





	public void updateGroupKeys(String groupName, UserToken t){

		// Get current iteration of group key
		ArrayList keyList = groupKeys.get(groupName);
		SecretKey oldKey = (SecretKey)keyList.get(keyList.size() - 1);

		try{
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);
			oos.writeObject(oldKey);
			byte[] oldKey_raw = bos.toByteArray();

			// Hash Key and add to groupKeys
			MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");
			ByteArrayInputStream bis = new ByteArrayInputStream(hash.digest(oldKey_raw));
			ObjectInputStream ois = new ObjectInputStream(bis);
			SecretKey newKey = (SecretKey) ois.readObject();

			keyList.add(newKey);
			groupKeys.put(groupName, keyList);

			// Send updated Key to Server
			Envelope msg = new Envelope("UPDATEKEY");
			Cipher cipher;
			
			cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, sym_K);

			bos = new ByteArrayOutputStream();
			oos = new ObjectOutputStream(bos);
			oos.writeObject(t);
			byte[] byteToken = bos.toByteArray();
			bos = new ByteArrayOutputStream();
			oos = new ObjectOutputStream(bos);
			oos.writeObject(newKey);
			byte[] byteKey = bos.toByteArray();

			byte[] t_enc = cipher.doFinal(byteToken);
			byte[] key_enc = cipher.doFinal(byteKey);
			msg.addObject(cipher.getIV()); 												// 0 => iv
			msg.addObject(t_enc); 																// 1 => token
			msg.addObject(cipher.doFinal(groupName.getBytes())); 	// 2 => groupName
			msg.addObject(key_enc); 															// 3 => newKey
		} catch (Exception e){
			e.printStackTrace();
		}
	}





	public boolean clientSRP (String user, String password)
	{
		Security.addProvider(new BouncyCastleProvider());
		SRP6Client client = new SRP6Client();
		client.init(p_2056,g_2056,new SHA256Digest(), rand);
		Envelope response2 = null;
		Envelope msg2 = new Envelope("SRP");
		BigInteger A = null, S = null;
		msg2.addObject(user);
		byte[] salt = new byte[0];
		try {
			A = client.generateClientCredentials(salt, user.getBytes(), password.getBytes());
			msg2.addObject(A);
			output.writeObject(msg2);
			response2 = (Envelope)input.readObject();

		} catch(IOException io)
		{
			System.out.println(io.getLocalizedMessage());
		} catch(ClassNotFoundException c)
		{
			System.out.println(c.getMessage());
		}
		try {
			S = client.calculateSecret((BigInteger)response2.getObjContents().get(0));
		} catch(CryptoException c)
		{
			System.out.println(c.getMessage());
		}
		sym_K = new SecretKeySpec(S.toByteArray(), 0, 32, "AES");

		//write sym_k to file server shared txt file.

		byte[] chal1 = (byte[]) response2.getObjContents().get(1);

		return challengeResp(chal1);
	}

	private boolean challengeResp(byte[] chal)
	{
		Envelope response1 = null;
		Envelope msg1 = new Envelope("CHAL");


		SecureRandom random = new SecureRandom();
        byte[] chal2 = new byte[12];
        random.nextBytes(chal2); // 96 bit challenge

        Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
	        cipher.init(Cipher.ENCRYPT_MODE, sym_K);
	        byte[] enc_chal = cipher.doFinal(chal2);
	        msg1.addObject(cipher.getIV());
	        msg1.addObject(enc_chal);
	        output.writeObject(msg1);
	        response1 = (Envelope)input.readObject();
	        if(response1.getObjContents().size() < 2)
	        	return false;

		    byte[] iv = (byte[])response1.getObjContents().get(0);
	        byte[] c2Cipher = (byte[])response1.getObjContents().get(1);
	        cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
	        byte[] c2_dec = cipher.doFinal(c2Cipher);

			return Arrays.equals(chal2, c2_dec);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | ClassNotFoundException | InvalidAlgorithmParameterException e) {

			e.printStackTrace();
		}
		return false;
	}

	 public UserToken getToken(String username)
	 {
		try
		{
			InputStream inStream = new FileInputStream("GroupServer.jks");
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(inStream, "password".toCharArray());
			X509Certificate cert=(X509Certificate) ks.getCertificate("selfsigned");
			PublicKey File_pub = (PublicKey) cert.getPublicKey();
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
	        cipher.init(Cipher.ENCRYPT_MODE, sym_K);

	        message.addObject(cipher.getIV());
			message.addObject(cipher.doFinal(username.getBytes())); //Add user name string
			message.addObject(File_pub);
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("OK"))
			{
				// If there is a token in the Envelope, return it
				/*********/
				// get encrypted token bits from response.
				byte[] iv = (byte[])message.getObjContents().get(0);
				byte[] t_d_enc = (byte[]) (message.getObjContents().get(1));
				byte [] tokenhash_enc = (byte[]) (message.getObjContents().get(3));
				byte [] tokensig_enc = (byte[]) (message.getObjContents().get(3));

				//decrypt token bits
				Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
				byte[] t_enc = tok.doFinal(t_d_enc);

				//token bits back to token Object
				ByteArrayInputStream byteStream = new ByteArrayInputStream(t_enc);
				ObjectInputStream objStream = new ObjectInputStream(byteStream);
				UserToken tokenT = (UserToken) objStream.readObject();

				// get hashed of token
				signedHash = tok.doFinal(tokenhash_enc);
				//get signature of token
				tokensig = tok.doFinal(tokensig_enc);

				return tokenT;
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

	 public boolean createUser(String username, String password)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				byte[] s = new byte[0];

				BigInteger x = SRP6Util.calculateX(new SHA256Digest(), g_2056, s, username.getBytes(), password.getBytes());
				BigInteger v = p_2056.modPow(x, g_2056);

				message.addObject(username); //Add user name string
				message.addObject(v); //Add password verifier
				output.writeObject(message); // Send message to GroupServer

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		        cipher.init(Cipher.ENCRYPT_MODE, sym_K);
		        message.addObject(cipher.getIV());
				message.addObject(cipher.doFinal(username.getBytes())); //Add user name string
				ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(byteStream);
				oos.writeObject(token);
				byte[] byteToken = byteStream.toByteArray();
				message.addObject(cipher.doFinal(byteToken)); // Add requester token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		        cipher.init(Cipher.ENCRYPT_MODE, sym_K);
		        message.addObject(cipher.getIV());
		        message.addObject(cipher.doFinal(groupname.getBytes())); //Add groupname string
				ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(byteStream);
				oos.writeObject(token);
				byte[] byteToken = byteStream.toByteArray();
				message.addObject(cipher.doFinal(byteToken)); // Add requester token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					output.reset();
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		        cipher.init(Cipher.ENCRYPT_MODE, sym_K);
		        message.addObject(cipher.getIV()); // add the IV
		        message.addObject(cipher.doFinal(groupname.getBytes())); //Add groupname string
				ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(byteStream);
				oos.writeObject(token);
				byte[] byteToken = byteStream.toByteArray();
				message.addObject(cipher.doFinal(byteToken)); // Add requester token
				output.writeObject(message);
				output.reset();

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return false;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		     cipher.init(Cipher.ENCRYPT_MODE, sym_K);
		     message.addObject(cipher.getIV()); // Send IV
		     message.addObject(cipher.doFinal(group.getBytes())); //Add groupname string
		     ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			 ObjectOutputStream oos = new ObjectOutputStream(byteStream);
			 oos.writeObject(token);
			 byte[] byteToken = byteStream.toByteArray();
			 message.addObject(cipher.doFinal(byteToken)); // Add requester token
			 output.writeObject(message);
			 output.reset();

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				byte[] iv = (byte[])response.getObjContents().get(0);
				byte[] members_enc = (byte[])response.getObjContents().get(1);
				Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
				tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
				byte[] members = tok.doFinal(members_enc);
				bytesToStringList(members);
				return bytesToStringList(members); //This cast creates compiler warnings. Sorry.
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

	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			     cipher.init(Cipher.ENCRYPT_MODE, sym_K);
			     message.addObject(cipher.getIV()); // Send IV
			     message.addObject(cipher.doFinal(username.getBytes())); // Username
			     message.addObject(cipher.doFinal(groupname.getBytes())); //Add groupname string
			     ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				 ObjectOutputStream oos = new ObjectOutputStream(byteStream);
				 oos.writeObject(token);
				 byte[] byteToken = byteStream.toByteArray();
				 message.addObject(cipher.doFinal(byteToken)); // Add requester token
				 output.writeObject(message);
				output.reset();

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			     cipher.init(Cipher.ENCRYPT_MODE, sym_K);
			     message.addObject(cipher.getIV()); // Send IV
			     message.addObject(cipher.doFinal(username.getBytes())); // Username
			     message.addObject(cipher.doFinal(groupname.getBytes())); //Add groupname string
			     ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
				 ObjectOutputStream oos = new ObjectOutputStream(byteStream);
				 oos.writeObject(token);
				 byte[] byteToken = byteStream.toByteArray();
				 message.addObject(cipher.doFinal(byteToken)); // Add requester token
				 output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				//e.printStackTrace(System.err);
				return false;
			}
	 }

}

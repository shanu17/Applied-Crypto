/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.io.*;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class GroupThread extends Thread
{
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
	private SecretKey sym_K;
	private final Socket socket;
	private GroupServer my_gs;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	/*	try{
			final PemReader pemReader = new PemReader(new FileReader("group_server_id_rsa.pub"));
		    final PemObject pemObject = pemReader.readPemObject();
		    final byte[] pemContent = pemObject.getContent();
		    //final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemContent);
		    final KeyFactory keyFactory;
		    //final PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);
		    pemReader.close();
		}catch(IOException e){
			System.err.format("IOException: %s%n", e);
		} */
	}
	private BigInteger getSessionKey(String username, BigInteger A)
	{
		Security.addProvider(new BouncyCastleProvider());
		BigInteger B = null;
	    BigInteger S = null;

	    SRP6Server server = new SRP6Server();

	    server.init(p_2056, g_2056, my_gs.userList.getPass(username), new SHA256Digest(), new SecureRandom());
	    B = server.generateServerCredentials();
	    try {
	    	S = server.calculateSecret(A);
	    }catch (CryptoException cry)
	    {
	    	System.out.println(cry.getMessage());
	    }
	    sym_K = new SecretKeySpec(S.toByteArray(), 0, 32, "AES");

	    return B;
	}

	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			byte[] chal1 = new byte[12];
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			//System.out.println("Checking ADMIN...");
			//ArrayList<String> adminusers = my_gs.groupList.getGroupUsers("ADMIN");
			//for (String user : adminusers){
				//System.out.println(user);
			//}

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				//Handler to authenticate SRP calls
				if(message.getMessage().equals("SRP"))
				{
					if(message.getObjContents().size() < 2)
						response = new Envelope("FAIL");
					else {
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String) message.getObjContents().get(0);
								BigInteger A = (BigInteger) message.getObjContents().get(1);
								BigInteger B = getSessionKey(username, A);
								SecureRandom random = new SecureRandom();
								random.nextBytes(chal1);

								if(B!=null)
								{
									response = new Envelope("OK");
									response.addObject(B);
									response.addObject(chal1);
								}
							}
						}

					}
				}
				if(message.getMessage().equals("CHAL")) // Client wants the challenge
				{
					if(message.getObjContents().size() < 3)
						response = new Envelope("FAIL");
					else
					{
						response = new Envelope("FAIL");
						byte[] iv = (byte[])message.getObjContents().get(0);
						byte[] chal1Cipher = (byte[])message.getObjContents().get(1);
						byte[] chal2 = (byte[])message.getObjContents().get(2);

						Cipher challenge1 = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						challenge1.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
						byte[] chal1_dec = challenge1.doFinal(chal1Cipher);

						if(!Arrays.equals(chal1, chal1_dec))
						{
							output.writeObject(response);
							System.out.println("Error not the same challenge");
						}
						else
						{
							response = new Envelope("OK");
							Cipher challenge2 = Cipher.getInstance("AES/CTR/NoPadding", "BC");
							challenge2.init(Cipher.ENCRYPT_MODE, sym_K);
							byte[] chal2_enc = challenge2.doFinal(chal2);
							response.addObject(challenge2.getIV());
							response.addObject(chal2_enc);

							output.writeObject(response);
						}
					}
				}

				if(message.getMessage().equals("GETKEYS"))
				{
					response = new Envelope("FAIL");

					try {
						byte[] iv = (byte[])message.getObjContents().get(0);
						Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
						byte[] token_dec = cipher.doFinal((byte[])message.getObjContents().get(1));

						ByteArrayInputStream bis = new ByteArrayInputStream(token_dec);
						ObjectInputStream ois = new ObjectInputStream(bis);
						UserToken tokenT = (UserToken) ois.readObject();

						HashMap<String, ArrayList<SecretKey>> keysMap = new HashMap<>();
						ArrayList<String> groups = tokenT.getGroups();
						for (String g : groups){
							keysMap.put(g, my_gs.groupKeys.get(g));
						}

						response = new Envelope("OK");
						cipher.init(Cipher.ENCRYPT_MODE, sym_K, new IvParameterSpec(iv));
						response.addObject(iv);

						ByteArrayOutputStream bos = new ByteArrayOutputStream();
						ObjectOutputStream oos = new ObjectOutputStream(bos);
						oos.writeObject(keysMap);
						byte[] map_raw = bos.toByteArray();
						response.addObject(cipher.doFinal(map_raw));

					} catch (Exception ex){
						ex.printStackTrace();
					}
					output.writeObject(response);
					output.reset();
				}






				if(message.getMessage().equals("UPDATEKEY"))
				{
					byte[] iv = (byte[])message.getObjContents().get(0); // GET IV
					response = new Envelope("FAIL");
					try{
						Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
						byte[] token_dec = cipher.doFinal((byte[])message.getObjContents().get(1));
						String groupName = new String(cipher.doFinal((byte[])message.getObjContents().get(2)));
						byte[] key_dec = cipher.doFinal((byte[])message.getObjContents().get(3));

						ByteArrayInputStream bis = new ByteArrayInputStream(token_dec);
						ObjectInputStream ois = new ObjectInputStream(bis);
						UserToken tokenT = (UserToken) ois.readObject();

						bis = new ByteArrayInputStream(key_dec);
						ois = new ObjectInputStream(bis);
						SecretKey newKey = (SecretKey) ois.readObject();

						ArrayList<SecretKey> entry = my_gs.groupKeys.get(groupName);
						entry.add(newKey);
						my_gs.groupKeys.put(groupName, entry);

						response = new Envelope("OK");
					} catch (Exception ex){
						ex.printStackTrace();
					}
					output.writeObject(response);
					output.reset();
				}







				if(message.getMessage().equals("ADDKEY"))
				{
					byte[] iv = (byte[])message.getObjContents().get(0); // GET IV
					response = new Envelope("FAIL");
					try{
						Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						cipher.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
						byte[] token_dec = cipher.doFinal((byte[])message.getObjContents().get(1));
						String groupName = new String(cipher.doFinal((byte[])message.getObjContents().get(2)));
						byte[] key_dec = cipher.doFinal((byte[])message.getObjContents().get(3));

						ByteArrayInputStream bis = new ByteArrayInputStream(token_dec);
						ObjectInputStream ois = new ObjectInputStream(bis);
						UserToken tokenT = (UserToken) ois.readObject();

						bis = new ByteArrayInputStream(key_dec);
						ois = new ObjectInputStream(bis);
						SecretKey key = (SecretKey) ois.readObject();

						ArrayList<SecretKey> entry = new ArrayList<SecretKey>();
						entry.add(key);
						my_gs.groupKeys.put(groupName, entry);
						response = new Envelope("OK");

					} catch(Exception ex){
						ex.printStackTrace();
					}
					output.writeObject(response);
					output.reset();
				}

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					byte[] iv = (byte[])message.getObjContents().get(0); // GET IV
					Cipher plain_user = Cipher.getInstance("AES/CTR/NoPadding", "BC");
					plain_user.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv));
					byte[] username_dec = plain_user.doFinal((byte[])message.getObjContents().get(1));
					PublicKey File_pub = (PublicKey) message.getObjContents().get(2);
					String username = new String(username_dec); //Get the username
					if(my_gs.userList.checkUser(username) == false)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
					    Date date= new Date();
					    long time = date.getTime();
						//Create a token
						UserToken yourToken = createToken(username, File_pub, time);

						// change token to bit stream
						ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
						ObjectOutputStream oos = new ObjectOutputStream(byteStream);
						oos.writeObject(yourToken);
						byte[] byteToken = byteStream.toByteArray();

						// encrypt token bits with sym_K
						Cipher t = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						t.init(Cipher.ENCRYPT_MODE, sym_K);
						byte[] token_enc = t.doFinal(byteToken);

						// add btye token to the response[0]
						Envelope response_token = new Envelope("OK");


						// find the hash of token bits using SHA256
						SHA256Digest digest = new SHA256Digest();
						byte[] output_hash = new byte[digest.getDigestSize()];
						digest.update(byteToken, 0, byteToken.length);
						digest.doFinal(output_hash, 0);

						// sign token bit hash using the group servers public key
						Signature signature = Signature.getInstance("SHA1withRSA", "BC");
						SecureRandom random  = new SecureRandom();
				        signature.initSign((PrivateKey) my_gs.privateKey, random);
				        signature.update(output_hash);

				        byte[]  sigBytes = signature.sign();

						// encrypt token hash with sym_K
						Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						tok.init(Cipher.ENCRYPT_MODE, sym_K);
						byte[] tokenhash_enc = tok.doFinal(output_hash);

						// add signed token hash to response[1]
						response_token.addObject(tok.getIV()); // 0
						response_token.addObject(token_enc); //1
						response_token.addObject(tokenhash_enc);//2
						response_token.addObject(sigBytes);//3


						//Respond to the client. On error, the client will receive a null token

						output.writeObject(response_token);
						output.reset();
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								BigInteger password = (BigInteger)message.getObjContents().get(1); // Extract the password of the user

								if(createUser(username, password))
								{

									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								byte[] iv_deluser = (byte[])message.getObjContents().get(0);
								byte[] username_enc = (byte[])message.getObjContents().get(1); //Extract the username
								byte[] yourToken = (byte[])message.getObjContents().get(2); //Extract the token
								Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
								tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv_deluser));
								byte[] username_byte = tok.doFinal(username_enc);
								byte[] token_dec = tok.doFinal(yourToken);
								String username = new String(username_byte);
								//token bits back to token Object
								ByteArrayInputStream byteStream = new ByteArrayInputStream(token_dec);
								ObjectInputStream objStream = new ObjectInputStream(byteStream);
								UserToken tokenT = (UserToken) objStream.readObject();


								if(deleteUser(username, tokenT))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					if (message.getObjContents().size() < 2)
						response = new Envelope("FAIL-BADCONTENTS");
					else if (message.getObjContents().get(0) == null)
					{
						response = new Envelope("FAIL-BADGROUP");
					}
					else if (message.getObjContents().get(1) == null)
					{
						response = new Envelope("FAIL-BADTOKEN");
					}

					else
					{
						// Relevant info
						byte[] iv_creategrp = (byte[])message.getObjContents().get(0);
						byte[] groupname_enc = (byte[])message.getObjContents().get(1); //Extract the groupname
						byte[] yourToken = (byte[])message.getObjContents().get(2); // Extract the token

						Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv_creategrp));
						byte[] groupname_byte = tok.doFinal(groupname_enc);
						byte[] token_dec = tok.doFinal(yourToken);
						String groupname = new String(groupname_byte);
						//token bits back to token Object
						ByteArrayInputStream byteStream = new ByteArrayInputStream(token_dec);
						ObjectInputStream objStream = new ObjectInputStream(byteStream);
						UserToken tokenT = (UserToken) objStream.readObject();

						String requester = tokenT.getSubject();
						if(my_gs.groupList.checkGroup(groupname))
						{
							System.out.println("Group already exists");
							response = new Envelope("FAIL-BADGROUP");
						}
						else {
							// Add user to group
							my_gs.userList.addGroup(requester,groupname);
							my_gs.userList.addGroup(requester, groupname);
							my_gs.userList.addOwnership(requester, groupname);
							// Add group to my_gs.groupList
							my_gs.groupList.addGroup(groupname);
							my_gs.groupList.addMember(groupname, requester);
							my_gs.groupList.addGroupOwner(groupname, requester);
						response = new Envelope("OK");
						}
					}
					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					response = new Envelope("FAIL");
					if (message.getObjContents().size() < 2)
						response = new Envelope("FAIL-BADCONTENTS");
					else if (message.getObjContents().get(0) == null)
					{
						response = new Envelope("FAIL-BADGROUP");
					}
					else if (message.getObjContents().get(1) == null)
					{
						response = new Envelope("FAIL-BADTOKEN");
					}
					else
					{
						// Conditions Satisfied
						byte[] iv_deluser = (byte[])message.getObjContents().get(0);
						byte[] groupname_enc = (byte[])message.getObjContents().get(1); //Extract the groupname
						byte[] yourToken = (byte[])message.getObjContents().get(2); //
						Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv_deluser));
						byte[] groupname_byte = tok.doFinal(groupname_enc);
						byte[] token_dec = tok.doFinal(yourToken);
						String groupname = new String(groupname_byte);
						//token bits back to token Object
						ByteArrayInputStream byteStream = new ByteArrayInputStream(token_dec);
						ObjectInputStream objStream = new ObjectInputStream(byteStream);
						UserToken tokenT = (UserToken) objStream.readObject();
						String requester = tokenT.getSubject();
						if(my_gs.userList.getUserOwnership(requester).contains(groupname))
						{
							// requester is the group owner
							deleteGroup(groupname, tokenT);
							response = new Envelope("OK");
						}
					}
					//If the User is not the owner, response will have the message: FAIL
					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					response = new Envelope("FAIL");
					if (message.getObjContents().size() < 2)
						response = new Envelope("FAIL-BADCONTENTS");
					else if (message.getObjContents().get(0) == null)
					{
						response = new Envelope("FAIL-BADGROUP");
					}
					else if (message.getObjContents().get(1) == null)
					{
						response = new Envelope("FAIL-BADTOKEN");
					}
					else
					{
						// Conditions Satisfied
						byte[] iv_listgrp = (byte[])message.getObjContents().get(0);
						byte[] groupname_enc = (byte[])message.getObjContents().get(1); //Extract the groupname
						byte[] yourToken = (byte[])message.getObjContents().get(2); //
						Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv_listgrp));
						byte[] groupname_byte = tok.doFinal(groupname_enc);
						byte[] token_dec = tok.doFinal(yourToken);
						String groupname = new String(groupname_byte);
						//token bits back to token Object
						ByteArrayInputStream byteStream = new ByteArrayInputStream(token_dec);
						ObjectInputStream objStream = new ObjectInputStream(byteStream);
						UserToken tokenT = (UserToken) objStream.readObject();
						String requester = tokenT.getSubject();
						ArrayList<String> members = new ArrayList<String>();
						members = my_gs.groupList.getGroupUsers(groupname);
						response = new Envelope("OK");
						ByteArrayOutputStream baos = new ByteArrayOutputStream();
						DataOutputStream out = new DataOutputStream(baos);
						for (String element : members) {
						    out.writeUTF(element);
						}
						byte[] member_bytes = baos.toByteArray();
						response.addObject(member_bytes);
					}
					//If the User is not the owner, response will have the message: FAIL
					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					response = new Envelope("FAIL");
					if (message.getObjContents().size() < 3)
						response = new Envelope("FAIL-BADCONTENTS");
					else if (message.getObjContents().get(0) == null)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else if (message.getObjContents().get(1) == null)
					{
						response = new Envelope("FAIL-BADGROUP");
					}
					else if (message.getObjContents().get(2) == null)
					{
						response = new Envelope("FAIL-BADTOKEN");
					}
					else
					{
						// Conditions Satisfied

						byte[] iv_addusergroup = (byte[])message.getObjContents().get(0);
						byte[] username_enc = (byte[])message.getObjContents().get(1); //Extract the username
						byte[] groupname_enc = (byte[])message.getObjContents().get(2); // Extract the groupname
						byte[] yourToken = (byte[])message.getObjContents().get(3); // Extract token
						Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv_addusergroup));
						byte[] username_byte = tok.doFinal(username_enc);
						byte[] groupname_byte = tok.doFinal(groupname_enc);
						byte[] token_dec = tok.doFinal(yourToken);
						String username = new String(username_byte);
						String groupname = new String(groupname_byte);
						//token bits back to token Object
						ByteArrayInputStream byteStream = new ByteArrayInputStream(token_dec);
						ObjectInputStream objStream = new ObjectInputStream(byteStream);
						UserToken tokenT = (UserToken) objStream.readObject();
						String requester = tokenT.getSubject();
						if(my_gs.userList.getUserOwnership(requester).contains(groupname))
						{
							// requester is the group owner
							my_gs.userList.addGroup(username, groupname);
							my_gs.groupList.addMember(groupname, username);
							response = new Envelope("OK");
						}
					}
					//If the User is not the owner, response will have the message: FAIL
					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					response = new Envelope("FAIL");
					if (message.getObjContents().size() < 3)
						response = new Envelope("FAIL-BADCONTENTS");
					else if (message.getObjContents().get(0) == null)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else if (message.getObjContents().get(1) == null)
					{
						response = new Envelope("FAIL-BADGROUP");
					}
					else if (message.getObjContents().get(2) == null)
					{
						response = new Envelope("FAIL-BADTOKEN");
					}
					else
					{
						// Conditions Satisfied
						byte[] iv_addusergroup = (byte[])message.getObjContents().get(0);
						byte[] username_enc = (byte[])message.getObjContents().get(1); //Extract the username
						byte[] groupname_enc = (byte[])message.getObjContents().get(2); // Extract the groupname
						byte[] yourToken = (byte[])message.getObjContents().get(3); // Extract token
						Cipher tok = Cipher.getInstance("AES/CTR/NoPadding", "BC");
						tok.init(Cipher.DECRYPT_MODE, sym_K, new IvParameterSpec(iv_addusergroup));
						byte[] username_byte = tok.doFinal(username_enc);
						byte[] groupname_byte = tok.doFinal(groupname_enc);
						byte[] token_dec = tok.doFinal(yourToken);
						String username = new String(username_byte);
						String groupname = new String(groupname_byte);
						//token bits back to token Object
						ByteArrayInputStream byteStream = new ByteArrayInputStream(token_dec);
						ObjectInputStream objStream = new ObjectInputStream(byteStream);
						UserToken tokenT = (UserToken) objStream.readObject();
						String requester = tokenT.getSubject();
						if(my_gs.userList.getUserOwnership(requester).contains(groupname))
						{
							// requester is the group owner
							my_gs.userList.removeGroup(username, groupname);
							my_gs.groupList.removeMember(groupname, username);
							response = new Envelope("OK");
						}
					}
					//If the User is not the owner, response will have the message: FAIL
					output.writeObject(response);
					output.reset();
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			//e.printStackTrace(System.err);
		}
	}

	private void deleteGroup(String groupname, UserToken yourToken)
	{
		// Get list of group members, and remove each of them from the group
		ArrayList<String> members = new ArrayList<String>();
		members = my_gs.groupList.getGroupUsers(groupname);
		for(String user : members)
		{
			my_gs.userList.removeGroup(user, groupname);
			my_gs.userList.removeOwnership(user, groupname);
		}
		my_gs.groupList.deleteGroup(groupname);
		// Update your token to not include the removed group
		yourToken.removeGroup(groupname);
	}

	//Method to create tokens
	private UserToken createToken(String username, PublicKey key, long time)
	{
		UserToken yourToken;
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new user token with server's name, user's name, and user's groups
			yourToken = new UserToken(my_gs.name, username, my_gs.userList.getUserGroups(username), key, time);
		}
		else
		{
			// create empty token
			yourToken = new UserToken(my_gs.name, username, null, key, time);
		}
		return yourToken;

	}


	//Method to create a user
	private boolean createUser(String username, BigInteger password)
	{
		//String requester = yourToken.getSubject();

		//Check if username is not taken
		if(!my_gs.userList.checkUser(username))
		{
			my_gs.userList.addUser(username, password);
			return true;
		}
		else
			return false;

	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(deleteFromGroups.get(index), username);
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. UserToken must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new UserToken(my_gs.name, username, deleteOwnedGroup));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

}

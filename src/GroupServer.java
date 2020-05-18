/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;



public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
  public Key publicKey;
	public Key privateKey;
	public HashMap<String, ArrayList<SecretKey>> groupKeys; //Hashmap of "GroupID" => List(AESKey by generation)

	// create public/private key pair here. save the private here, print public to txt file.
	// create with Bouncy Castle (2048) privete/public key. use private key to sign everything

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
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
		try {
			InputStream inStream = new FileInputStream("GroupServer.jks");
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(inStream, "password".toCharArray());
			Key privateKey = (Key)ks.getKey("groupserver", "password".toCharArray());

			ks.load(inStream,"password".toCharArray());
			X509Certificate cert=(X509Certificate) ks.getCertificate("selfsigned");
			publicKey = (Key) cert.getPublicKey();
		} catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		groupKeys = new HashMap<String, ArrayList<SecretKey>>();
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");

		try {
			InputStream inStream = new FileInputStream("GroupServer.jks");
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(inStream, "password".toCharArray());
			Key privateKey = (Key)ks.getKey("groupserver", "password".toCharArray());

			ks.load(inStream,"password".toCharArray());
			X509Certificate cert=(X509Certificate) ks.getCertificate("selfsigned");
			publicKey = (Key) cert.getPublicKey();
		} catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		groupKeys = new HashMap<String, ArrayList<SecretKey>>();
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			// Only attempt to read the groupFile if the userFile reads correctly
			// Otherwise, a new userList must be created and therefore a new groupList
			try
			{
				fis = new FileInputStream(groupFile);
				groupStream = new ObjectInputStream(fis);
				groupList = (GroupList)groupStream.readObject();
			}
			catch(FileNotFoundException e)
			{
				System.out.println("GroupList File Does Not Exist.");
			}
			catch(IOException e)
			{
				System.out.println("Error reading from GroupList file");
				System.exit(-1);
			}
			catch(ClassNotFoundException e)
			{
				System.out.println("Error reading from GroupList file");
				System.exit(-1);
			}
			// fis.reset();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();

			String pass1 = null,pass2 = null;
			boolean c = false;
			while(!c)
			{
				System.out.println("Enter password for this account (must be more than 8 characters)");
				pass1 = console.next();
				System.out.println("Enter the same password again to confirm");
				pass2 = console.next();
				if(pass1.length() < 8 || pass2.length() < 8)
				{
					System.out.println("The password you entered is lesser than 8 characters");
					c = false;
				}else if (pass1.equals(pass2))
					c = true;
			}
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

			byte[] s = new byte[0];

			BigInteger x = SRP6Util.calculateX(new SHA256Digest(), g_2056, s, username.getBytes(), pass1.getBytes());
			userList.setPass(username, p_2056.modPow(x, g_2056));

			groupList = new GroupList();
			groupList.addGroup("ADMIN");
			groupList.addMember("ADMIN", username);
			groupList.addGroupOwner("ADMIN", username);
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			//e.printStackTrace(System.err);
		}

	}

}

//This thread saves the user list an the group list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			//e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 10 seconds
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					//e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);

	}
}

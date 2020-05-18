import java.util.*;
public class GroupList implements java.io.Serializable {
	/**
	 * Implements the list of all groups on the server
	 */
	private static final long serialVersionUID = 7600343803563417992L;
	private Hashtable<String, Group> list = new Hashtable<String, Group>();

    public synchronized String[] getAllGroups() {
        return list.keySet().toArray(new String[0]);
    }

	public synchronized void addGroup(String groupname)
	{
		Group newGroup = new Group();
		list.put(groupname, newGroup);
	}

	public synchronized void deleteGroup(String groupname)
	{
		list.remove(groupname);
	}

	public synchronized boolean checkGroup(String groupname)
	{
		if(list.containsKey(groupname))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	public synchronized ArrayList<String> getGroupUsers(String groupname)
	{
		return list.get(groupname).getUsers();
	}

	public synchronized String getGroupOwner(String groupname)
	{
		return list.get(groupname).getOwner();
	}

	public synchronized void addGroupOwner(String groupname, String username)
	{
		list.get(groupname).addOwner(username);
	}

	public synchronized void removeGroupOwner(String groupname, String username)
	{
		list.get(groupname).removeOwner(username);
	}

	public synchronized void addMember(String groupname, String username)
	{
		list.get(groupname).addUser(username);
	}

	public synchronized void removeMember(String groupname, String username)
	{
		try
		{
			list.get(groupname).removeUser(username);
		}
		catch (NullPointerException e)
		{
			System.out.println("Group " + groupname + " doesn't exist.");
		}

	}
	class Group implements java.io.Serializable {

		/**
		 * Individual group objects
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> users;
		private String owner;

		public Group()
		{
			users = new ArrayList<String>();
			owner = "";
		}

		public ArrayList<String> getUsers()
		{
			return users;
		}

		public String getOwner()
		{
			return owner;
		}

		public void addUser(String user)
		{
			users.add(user);
		}

		public void removeUser(String user)
		{
			if(!users.isEmpty())
			{
				if(users.contains(user))
				{
					users.remove(users.indexOf(user));
				}
			}
		}

		public void addOwner(String user)
		{
			owner = user;
		}

		public void removeOwner(String user)
		{
			owner = "";
		}
	}
}

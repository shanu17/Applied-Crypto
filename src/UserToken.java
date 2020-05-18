import java.util.ArrayList;
import java.util.Date;
import java.io.Serializable ;
import java.security.PublicKey;

public class UserToken implements UserTokenInterface, Serializable  {

    String tokenHolder;
    String serverName;
    ArrayList<String> groupList;
    PublicKey key;
    long time;
    int messageNumber;
    // Group init not included because users don't have init groups.
    public UserToken(String tokenHolder, String serverName){
        this.tokenHolder = tokenHolder;
        this.serverName = serverName;
        messageNumber = 0;
    }

    public UserToken(String server, String tokenHolder, ArrayList<String> groups, PublicKey File_pub){
        this.tokenHolder = tokenHolder;
        this.groupList = groups;
        this.serverName = server;
        this.key = File_pub;
        messageNumber = 0;
    }
    public UserToken(String server, String tokenHolder, ArrayList<String> groups, PublicKey File_pub, long t){
        this.tokenHolder = tokenHolder;
        this.groupList = groups;
        this.serverName = server;
        this.key = File_pub;
        this.time = t;
        messageNumber = 0;
    }
    public UserToken(String server, String tokenHolder, ArrayList<String> groups){
        this.tokenHolder = tokenHolder;
        this.groupList = groups;
        this.serverName = server;
        messageNumber = 0;
    }

    public void addFileKey(PublicKey File_pub)
    {
    	this.key = File_pub;
    }
    // used to add groups dynamically
    public void addGroup(String groupName){
        if(!groupList.contains(groupName)){
          groupList.add(groupName);
        } else{
          System.out.println(tokenHolder + " is already a member of this group.");
        }
    }

    // used to remove groups that the user leaves/blocked from
    public void removeGroup(String groupName){
        groupList.remove(groupName);
    }
    public PublicKey getPublicKey()
    {
    	return this.key;
    }
    
    public long getTime()
    {
    	return this.time;
    }
    //used to see if a user is already a member
    public boolean isMember(String groupName){
        return groupList.contains(groupName);
     }

     public String getSubject() {
        if(tokenHolder != null && !tokenHolder.isEmpty()){
          return tokenHolder;
        }else{
          System.out.println("Error User Token, No Token Holder");
          return null;
        }
      }

      public String getIssuer(){
        if(serverName != null && !serverName.isEmpty()){
          return serverName;
        }else{
          System.out.println("Error User Token, No Server");
          return null;
        }
      }

      public void incMessageNumber(){
        messageNumber++;
      }

      public void forceUpdateMessageNumber(int num){
        messageNumber = num;
      }

      public int getMessageNumber(){
        return messageNumber;
      }

      public boolean authMessageNumber(int num){
        if(num <= messageNumber){
          return false;
        }else{
          if(num+1 != messageNumber){
            messageNumber = num;
            return true;
          }
          return true;
        }

      }

      public ArrayList<String> getGroups(){
        try{
          if(!groupList.isEmpty()){
            return groupList;
          }else{
            System.out.println("User is not apart of any groups yet.");
            return null;
          }
        }catch(Exception e){
          System.out.println("\n\n\t Heads up! The server updates every 5 minutes so a new group may not be visible yet. \n\tTry again in a bit!");
        }
        return null;
      }
    }

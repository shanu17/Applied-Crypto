import java.util.List;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.HashMap;

class ClientDriver {
  public static void main(String[] args){

    String defaultGroupAddress = "127.0.0.1";
    int defaultGroupPort = 8765;
    String defaultFileAddress = "127.0.0.1";
    int defaultFilePort = 4321;

    Scanner keyboard = new Scanner(System.in);
    String input="";
    GroupClient groupuser = new GroupClient();
    FileClient fileuser = new FileClient();

    boolean check_connection = true;
    boolean resp;

    String group_addr = "";
    int group_port = 0;
    String file_addr = "";
    int file_port = 0;

    do {
    System.out.println("\t\t Welcome!!x\n\n");
    System.out.println("\n PLEASE ENTER ONE OF THE FOLLOWING:\n");
    System.out.println("\t[D]\t Use the default addresses and ports for the Group and File Servers.");
    System.out.println("\t[N]\t Input your own");
    System.out.print("\t>");
    input = keyboard.nextLine();
    while(true){
      if (input.equalsIgnoreCase("D"))
      {
        group_addr = defaultGroupAddress;
        group_port = defaultGroupPort;
        file_addr = defaultFileAddress;
        file_port = defaultFilePort;
        break;
      }
      else if (input.equalsIgnoreCase("N"))
      {
        System.out.print("\nEnter the group server IP address [string ex:\'123.4.5.6..\']> ");
        group_addr = keyboard.nextLine();                 // Get group server address from the user
        System.out.print("\nEnter the group server port [number]> ");
        group_port = keyboard.nextInt();
        keyboard.nextLine();
        System.out.print("\nEnter the file server IP address [string ex:\'123.4.5.6..\']> ");
        file_addr = keyboard.nextLine();                    // Get file server address from the user
        System.out.print("\nEnter the file server port [number]> ");
        file_port = keyboard.nextInt();
        keyboard.nextLine();
        break;
      }
      else
      {
        System.out.print("\n\t[ERROR] Please enter D for defaults and N for non-defaults >");
        input = keyboard.nextLine();
      }
    }

    	try {
    		if(!groupuser.connect(group_addr, group_port) || !fileuser.connect(file_addr, file_port))
    		{
    			check_connection = false;
    		}

    	}
    	catch(NumberFormatException e) {
    		System.out.println("Enter a valid port number or valid address for group/file server");
    		check_connection = false;
    	}

    }while(!check_connection);             // Runs loop until it connects to the servers


    printnewuser();
    input = (keyboard.nextLine()).toUpperCase();
    boolean check = false;
    UserToken t = null;
    while(!check)
    {
    	switch(input)
        {
        case "A":
        	System.out.print("\t\nEnter your new username > ");
        	String username = keyboard.nextLine();
        	System.out.print("\t\nEnter your new password (greater than 8 characters)> ");
        	String password1 = keyboard.nextLine();
        	System.out.print("\t\nEnter the password again >");
        	String password2 = keyboard.nextLine();
        	if(password1.length() <8 || password2.length() <8){
        		System.out.println("\t\nYour password is too short WHAT WERE YOU THINKING!\t\n");
        		break;
        	}else if(!password1.equals(password2)){
        		System.out.println("\t\nPasswords do not match");
        		break;
        	}
        	resp = groupuser.createUser(username, password1);
        	if(resp){
        		System.out.println("\t\nUser created successfully");
        		t = groupuser.getToken(username);
        		if(!fileuser.send_token(t))
        		{
        			System.exit(0);
        		}
        	}else{
        		System.out.println("\t\nFailed to create user");
          }
        	check = true;
        	break;
        case "B":
        	System.out.print("\t\nEnter your username: >");
        	username = keyboard.nextLine();
        	System.out.print("\t\nEnter your password: >");
        	password1 = keyboard.nextLine();
        	resp = groupuser.clientSRP(username, password1);
        	if(resp){
        		System.out.println("Logged in successfully");
        		t = groupuser.getToken(username);
        		if(!fileuser.send_token(t))
        		{
        			System.exit(0);
        		}
        		check = true;
        		groupuser.getGroupKeys(t);
        	}else{
        		System.out.println("Failed to login");
          }
        }
    }
    // getUserName();

    while(!input.equals("X")){
          if(t.getGroups()==null){
            printMenu();
          }
          else if(!t.getGroups().contains("ADMIN"))
        	{
            printMenu();
        	}
        	else
        	{
            printAdminMenu();

        	}

      input = (keyboard.nextLine()).toUpperCase();
      System.out.println("you entered: "+ input);

      switch(input){
        case "D":
          printRemoveUserMenu();
          String deluser = keyboard.nextLine();
          UserToken token_deluser = groupuser.getToken(deluser);
          if(token_deluser.getGroups().contains("ADMIN")) {
        	  System.out.println("Cannot delete an admin sorry!!!!!!");
          }
          else {
        	  resp = groupuser.deleteUser(deluser, t);
        	  if(resp) {
        		  System.out.println("Deleted user sucessfully");
        	  }
        	  else {
        		  System.out.println("Failed to delete User");
        	  }
          }
          break;
        case "F":
         welcomeMenu("FilePile");
          String groupname = "Pasta"; //initialized to this temp thing.
            while(!input.equals("<")){
              printMenu_file();
              input = (keyboard.nextLine()).toUpperCase();
              System.out.println("[File Side] you entered: "+ input);
              switch(input){
                case "L":
                  List<String> list_all = fileuser.listFiles(t);
                  printAllMenu("file", list_all, "admin");
                  break;
                case "U":
                  printAddFile();
                  String SourceFile= keyboard.nextLine();
                  System.out.print("\n\t Name of the file to be saved locally >");
                  String DestFile= keyboard.nextLine();
                  System.out.print("\n\t Enter the name of the group this file is a part of >");
                  groupname= keyboard.nextLine();
                  if(t.isMember(groupname))
                  {
                	  resp = fileuser.upload(SourceFile, DestFile, groupname, t);
                	  if(resp) {
                		  System.out.println("File Upload Successful");
                	  }
                  }else{
                    System.out.println("\n\t*Error, upload, not valid member of " + groupname);
                  }
                  break;
                case "D":
                  printAllMenu("file", fileuser.listFiles(t), "amy");
                  // print all menu prints with number.
                  System.out.print("Enter the source Name > ");
                  String s=keyboard.nextLine();
                  System.out.print("Enter the local destination path >");
                  String d=keyboard.nextLine();
                  fileuser.download(s, d, t);
                  break;
                case "Z":
                  printAllMenu("file",fileuser.listFiles(t), "amy");
                  System.out.print("Which file would you like you Delete? > ");
                  String delfile = keyboard.nextLine();
                  fileuser.delete(delfile, t);
                  break;
              }
            }
          break;
        case "C":
        	printCreateGroupMenu();
        		String tempName = keyboard.nextLine();
        		if(groupuser.createGroup(tempName, t)) {
        			System.out.println("\n \t Success! "+tempName +" has been added to the group list.");
            	System.out.println("\t You can now access "+tempName +"\'s files when you access the server with [F].");
              groupuser.addNewGroupKey(tempName, t);
        		}
        		else {
        			System.out.println("\n\t Couldn't create group!");
        		}

        	break;
        case "R":
        	System.out.println("Enter the name of the group you want to delete");
          	String groupname_Remove = keyboard.nextLine();
          	groupuser.deleteGroup(groupname_Remove, t);
          	break;
        case "G":
          try
          {
            printAllMenu("Group", t.getGroups(), "Leah");
          } catch (Exception e)
          {
            System.out.println("You Are not in any groups");
          }
          break;
        case "H":
        	printHelpList();
          break;
        case "Y":
            printAddUserMenu();
            String addusergroup = keyboard.nextLine();
            System.out.println(" Enter the groupname:");
            System.out.print("\t ADD>");
            groupname = keyboard.nextLine();
            resp = groupuser.addUserToGroup(addusergroup, groupname, t);
            if(resp) {
              System.out.println("Added User to Group successfully");
            }
            else
            {
              System.out.println("Failes to add User to Group");
            }
            break;

        case "Z":
            printRemoveUserMenu();
            String remUser = keyboard.nextLine();
            System.out.println("Enter the name of the group to delete user from");
            System.out.println("\t GROUP NAME >");
            groupname = keyboard.nextLine();
            resp = groupuser.deleteUserFromGroup(remUser, groupname, t);
            groupuser.updateGroupKeys(groupname, t);
            if(resp){
              System.out.println("Sucessfully removed " + remUser + " from the group. \n \t * It may take a few minutes for this change to update.");
            }else{
              System.out.println("\t\t * Error, removal not successful. Please check permissions.");
            }
            break;
        case "U":
          System.out.print("\n\t What group roster would you like to see? >");
          String gName = keyboard.nextLine();
          printAllMenu("user", groupuser.listMembers(gName, t),"Leah");
          break;
        case "X":
          System.out.println("Goodbye!");
          groupuser.disconnect();
          fileuser.disconnect();
          break;
        default:
        System.out.println("\t> * Error - That charcter is not recognized by the system");
        System.out.println("\t    please try another.");
      }
    }
  }



  public static void printMenu(){
    System.out.println("*--------------------------------------------------------");
    System.out.println("|\t[F]\t List FileServer Options\n");

    System.out.println("\t[C]\t Create Group");
    System.out.println("\t[R]\t Remove Group\n");

    System.out.println("\t[G]\t Print Group List");
    System.out.println("\t[U]\t Print User List of a Group\n");

    System.out.println("\t[Z]\t Remove a specific member from");
    System.out.println("\t\t a group.");
    System.out.println("\t[Y]\t Add a specific member to");
    System.out.println("\t\t a group.\n");

    System.out.println("\n\t[H]\t Help");
    System.out.println("|\t[X]\t Exit");
    System.out.println("*--------------------------------------------------------");
    System.out.print("\t >");
  }

  public static void printAdminMenu(){
    System.out.println("*--------------------------------------------------------");
    //System.out.println("|\t[F]\t List FileServer Options");
    System.out.println("\t[D]\t Delete User");
    System.out.println("\t[R]\t Remove Group\n");

    System.out.println("\t[U]\t Print User List of a Group\n");

    System.out.println("\n\t[H]\t Help");
    System.out.println("|\t[X]\t Exit");
    System.out.println("*--------------------------------------------------------");
    System.out.print("\t >");
  }

  public static void printAddUserMenu(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t ADD NEW USER");
    System.out.println("\n\n Enter the user name of the new member:");
    System.out.print("\t ADD >");
  }

  public static void printRemoveUserMenu(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t REMOVE A CURRENT USER");
    System.out.println("\n\n Enter the user name of the member you would like to remove");
    System.out.print("\t REMOVE >");
  }

  public static void printRemoveByNumberMenu(String type, List<String> List, String admin){
    System.out.println("\n ---- ALL CURRENT "+ type.toUpperCase() +"S ---- ");
    System.out.println(" type the number listed by the "+ type+ " you would like to remove.");
    System.out.println(" TYPE Q TO QUIT");
    if(type.toLowerCase().equals("member")){
      System.out.println(" \t [A]\t"+ admin + " (cannot be removed) \n");
    }
    for(int i = 0; i < List.size(); i++){
      System.out.println("\t [" + i + "] \t" +List.get(i));
    }
  }

  public static void printAllMenu(String type, List<String> List, String admin){
    if(List.size()==0){
      System.out.println("\n EMPTY * There are currently no "+ type +"s. ");
    }else{
      System.out.println("\n ---- ALL CURRENT "+ type.toUpperCase() +"S ---- \n");
      if(type.toLowerCase().equals("member")){
        System.out.println("  Admin(s):");
        System.out.println(" \t [A]\t"+ admin + " (cannot be removed) \n");
        System.out.println("  General:");
      }
      for(int i = 0; i < List.size(); i++){
        System.out.println("\t [" + i + "] \t" +List.get(i));
      }
    }
    System.out.println("\n");
  }

  public static void printGroupMenu(List<String> groups){
    System.out.println("\n ---- ALL CURRENT GROUPS ---- ");
    System.out.println(" type the number of the Group File Server you would like to join");
    System.out.println(" TYPE Q TO QUIT");
    for(int i = 0; i < groups.size(); i++){
      System.out.println("\t [" + i + "] \t" +groups.get(i));
    }
  }

  public static void printDeleteGroupMenu(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t REMOVE A CURRENT GROUP");
    System.out.println("\n\n Enter the user name of the group you would like to remove");
    System.out.println("\t * or type \' -List \' to use EASY Remove. \n");
    System.out.print("\t REMOVE >");
  }

  public static void printCreateGroupMenu(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t CREATE NEW GROUP");
    System.out.println("\n\n Enter the name of the group you'd like to create");
    System.out.print("\t >");
  }

  public static void printHelpList(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t HELP:");
    System.out.println("\n\n\t Enter any of the following key letters to do their actions,");
    System.out.println("\t if you are an admin your changes will effect the entire server. \n");
    System.out.println("|\t To leave the application you can hit X.");
    System.out.println("*-------------------------------------------------------");
  }

  public static void printRemoveFromGroupMenu(List<String> group){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t REMOVE A SPECIFIC MEMBER FROM A GROUP");
    System.out.println("\t Please select the group from which you would like to \n\t remove a member: ");
    System.out.println("\n\t TYPE Q TO QUIT\n");
    for(int i = 0; i < group.size(); i++){
      System.out.println("\t [" + i + "] \t" +group.get(i));
    }
  }

  public static void getUserName(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t Please enter a user name:");
    System.out.print("\t> ");
  }

   public static void userNameInvalid(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t That name is taken, please pick another:");
    System.out.print("\t> ");
  }

    public static void welcomeMenu(String serverName){
    System.out.println("\n\n\tWelcome to " + serverName+ " !!");
    System.out.println("\n\n *** PAY ATTENTION TO THE COMMANDS HAVE CHANGED.\n\n\n");
  }

  public static void printAddFile(){
    System.out.println("*-------------------------------------------------------");
    System.out.println("|\t ADD A NEW FILE");
    System.out.print("\n\t PATH OF LOCAL FILE TO UPLOAD >");
  }

  public static void printnewuser()
  {
	  System.out.println("\t[A]\t New User");
	  System.out.println("\t[B]\t Returning User");
  }

  public static void printMenu_file(){
    System.out.println("*--------------------------------------------------------");
    System.out.println("\t[L]\t Print File List\n");
    System.out.println("\t[U]\t Upload File");
    System.out.println("\t[D]\t Download File");
    System.out.println("\t[Z]\t Delete File");


    System.out.println("|\t[<]\t Return to Menu");
    System.out.println("*--------------------------------------------------------");
    System.out.print("\t >");
  }

}

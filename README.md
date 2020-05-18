# Applied-Crypto
Applied Cryptography and Network Security Fall 2019 Project

# FileSharing Usage Information

## USAGE:
 To start Group Server: java RunGroupServer [(optional) port number]
 When the group server is first started, there are no users or groups. Since 
 there must be an administer of the system, the user is prompted via the console
 to enter a username. This name becomes the first user and is a member of the
 ADMIN group.  Also, no groups exist.  The group server will by default
 run on port 8765, but a custom port can be passed as the first command line
 argument.

 To start the File Server: java RunFileServer [(optional) port number]
 The file server will create a shared_files inside the working directory if one 
 does not exist. The file server is now online.  The file server will by default
 run on port 4321, but a custom port can be passed as the first command line
 argument.

 To reset the File server completely, delete FileList.bin and the shared_files 
 directory.
 To reset the Group Server, delete UserList.bin.
 
 Note that this implementation supports server side directories.

## Compile
Once inside src/ folder,

COMPILE: javac *.java

COMPILE bouncycastle : javac -cp :./bcprov-jdk15on-163.jar [FILE].java
run: java -cp :./bcprov-jdk15on-163.jar [FILE]

# TCP chat client
import socket, select, string, sys,time,signal,errno
import Client,User


# Create a new chat client instance
client = Client.Client()


# Handler for Control + C keyboard interrupt
def sigintHandler(signum,frame):
    sys.stdout.write("Logging out\n")
    sys.stdout.flush()
    client.processCommand("logout","logout")


# Handler to send heartbeat message
def heartBeatHandler(signum,frame):
    client.connChatServ(client.host,client.port)
    if(client.name):
        msg = str("alive" + ','+ client.name)
        client.sendMsg(client.clientSocket,msg)
        client.deInitConn(client.clientSocket)
    # This is in case the user waits too long to input username
    # In that case the client program doesn't know user name
    else:
        sys.stdout.write("\nYou took too long to enter username. Please try again\n")
        sys.stdout.flush()
        sys.exit()


# Set the time interval for sending heartbeat
signal.setitimer(signal.ITIMER_REAL,client.heartBeatInterval,client.heartBeatInterval)
# Set up signal check for Control +C interrupt
signal.signal(signal.SIGINT,sigintHandler)
# Set up alarm to remind client to send heartbeat
signal.signal(signal.SIGALRM,heartBeatHandler)


#main function
if __name__ == "__main__":

    if(len(sys.argv) < 3) :
        print 'Usage : python tcp_chat_client.py hostname ports'
        sys.exit()
    BUFFFER = 4096
    host = sys.argv[1]
    port = int(sys.argv[2])

    client.host = host
    client.port = port

    #Create a socket so that server can contact the client
    client.createListSocket()
    client.socketList.append(client.listenSocket)

    # Connect to the chat server
    client.connChatServ(host,port)

    # Authentication prompt
    # Client prompts for username and password and sends it to the server
    client.getUsrPwd()

    # After authenticating deInit TCP connection
    client.deInitConn(client.clientSocket)

    # Run this loop forever : this is the loop for listening incoming connection requests and messages
    while 1:
        try:
            # Get the list sockets which are readable
            read_sockets, write_sockets, error_sockets = select.select(client.socketList , [], [])


            for sock in read_sockets:
                # Incoming connection request from remote server or host
                if sock == client.listenSocket:
                    sockfd, addr = client.listenSocket.accept()
                    client.socketList.append(sockfd)

               # User input
                elif(sock == sys.stdin):
                    # Process user commands
                    if(client.online):
                        msg = sys.stdin.readline()
                        command = msg.split()[0]
                        client.processCommand(command,msg)
                        sys.stdout.write('>')
                        sys.stdout.flush()


                # Server forwarding a message or another user sending private chat --> this is received on listenSocket
                else:
                    if(client.online !=  False):
                        data = sock.recv(BUFFFER)

                        if data:
                            # Same user has logged in from another IP/terminal
                            if(data == "logout_duplicate"):
                                # De Init the TCP connection
                                client.deInitConn(sock)
                                sys.stdout.write("note:Someone else has logged in from the some ID.\n")
                                sys.stdout.write("Logging out\n")
                                sys.stdout.flush()
                                client.listenSocket.close()
                                sys.exit()

                            # Server has send the reply to request for list of online users
                            elif (data.split(',')[0] == "online"):
                                # Check if list is empty
                                if(len(data.split(',')) > 1):
                                    userList = data.split(',',1)[1]
                                    for user in userList.split(','):
                                        sys.stdout.write(user+"\n"+">")
                                else:
                                    sys.stdout.write("note:No one seems to be online\n>")
                                sys.stdout.flush()
                                # De Initialize TCP connection
                                client.deInitConn(sock)

                            # Another user wants to private chat with the client. Ask for consent
                            elif(data.split(',')[0] == "private_consent"):
                                client.deInitConn(sock)
                                requester = data.split(',')[1]
                                sys.stdout.write("note:User "+requester+" wants to chat privately.\n")
                                sys.stdout.write(">Enter <consent " +requester+" yes/no> if you consent!")
                                sys.stdout.write("\n>")
                                sys.stdout.flush()

                            # Server has send a reply to the request for address of another user
                            elif(data.split(',')[0] == "getaddress"):
                                # This user has been blocked by the other user
                                if(data.split(',')[1] == "blocked"):
                                    sys.stdout.write("note:Information not available as user has blocked you!\n>")
                                    sys.stdout.flush()


                                # Other user is offline
                                elif(data.split(',')[1] == "offline"):
                                    sys.stdout.write("note:Requested User is offline!\n>")
                                    sys.stdout.flush()

                                # User has said no to the request for private chat
                                elif(data.split(',')[1] == "no"):
                                    sys.stdout.write("note:User has rejected request for private chat!\n>")
                                    sys.stdout.flush()

                                else:
                                    # Save the ip and port for private chat
                                    user = data.split(',')[1]
                                    clientIP = data.split(',')[2]
                                    clientPort =int(data.split(',')[3])
                                    sys.stdout.write("note:You can now start private chat with "+\
                                                     user + "!\n>")
                                    sys.stdout.flush()
                                    client.privateMessageDB.update({user:(clientIP,clientPort)})

                                client.deInitConn(sock)


                            # Logout the client if server shuts down
                            elif(data == "shutdown"):
                                sys.stdout.write("Server is shutdown.\n")
                                sys.stdout.write(">Logging out\n")
                                sys.stdout.flush()
                                client.deInitConn(sock)
                                client.listenSocket.close()
                                del client
                                sys.exit()

                            # If it is some other data, print to the console
                            else:
                                sys.stdout.write(data)
                                sys.stdout.write('>')
                                sys.stdout.flush()
                                client.deInitConn(sock)

                        else:
                            sys.stdout.write("No data")
                            sys.stdout.flush()
                            sys.exit()

        # Error handle
        # The signal send by the heartbeat alarm shouldn't disturb the select.select
        # This is to ensure that the signal is non-blocking
        except select.error,v:
            if v[0] != errno.EINTR :
                raise
            else:
                continue












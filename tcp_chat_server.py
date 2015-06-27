# TCP Chat server
import socket,select,sys,signal,time,errno
import Server


# Create a new chat server instance
# Use default Port number and buffer size
server = Server.Server(0,0)


# Handler for control+C keyboard interrupt
def sigintHandler(signum,frame):
    sys.stdout.write("Shutting down server\n")
    sys.stdout.flush()
    server.shutdown()
    sys.exit()


# Handler to check if user's heartbeat
def checkUserAlive(signum,frame):
    if server.onlineConnList:
        for user in server.onlineConnList:
            sys.stdout.write("checking last heartbeat time of "+user+"\n")
            if((time.time() - server.userObj[user].heartBeatLast) >= server.heartBeatInterval):
                sys.stdout.write(user+ " no heartbeat. offline. removing user from the online list\n")
                sys.stdout.flush()
                server.cleanUpUser(user)
            else:
                sys.stdout.write(user+ " is alive\n")


# Set the timer for checking heartbeat
signal.setitimer(signal.ITIMER_REAL,server.heartBeatInterval,server.heartBeatInterval)
# Set up signal check for Control+C keyboard interrupt
signal.signal(signal.SIGINT,sigintHandler)
# Set up the alarm to notify the server to check for heartbeat
signal.signal(signal.SIGALRM,checkUserAlive)


# Main function
if __name__ == "__main__":


    #create, init and start listening on server_socket
    server.createInitServerSocket()

    # Add server welcome socket to the list of server connections
    server.appendToConnList(server.serverSocket)

    # Read user credentials and store in a dictionary
    server.storeUserCred()

    # Create User objects for each user
    server.createUser()

    print "Chat server started on port " + str(server.welcomePort)

    # Run this loop forever : this is the loop for listening incoming connection requests and messages
    while 1:
        try:
            # Get the list sockets which are ready to be read through select
            readSockets,writeSockets,errorSockets = select.select(server.socketConnList,[],[])


            for sock in readSockets:
                # New connection
                if sock == server.serverSocket:
                    # Accept new connection from user
                    sockfd, addr = server.serverSocket.accept()
                    server.appendToConnList(sockfd)
                else:
                    try:
                        # Socket from user
                        # Authenticate User if the user is new user
                        data = server.recvMsg(sock)
                        if(data.split(',')[0] == "newUser"):
                            server.authentClient(sock,data)
                            # DeInit the TCP connection after authenticating the user
                            server.deInitConn(sock)

                            username = data.split(',')[1]

                            # Notify the other users that this user is online
                            if(server.userObj[username].isOnline == True):
                                server.presenceBroadcast(username)

                                # Deliver the offline messages
                                if server.userObj[username].isOffLineMsg():
                                    server.deliverOfflineMsgs(username,server.userObj[username].offlineMessages)
                        else:
                            # User that is already connected and authenticated
                            # First word is the type of request

                            request = data.split(',')[0]
                            sender = data.split(',')[1]
                            # Check if user is online and authenticated
                            if((server.userObj[sender].isOnline) & (server.userObj[sender].isAuthenticated)):
                                server.processRequest(request,data)
                                # De Init TCP connection
                                server.deInitConn(sock)
                            else:
                                # User is offline in server's state when the heartbeat expires
                                # If we receive anything in the name of said user don't process it
                                print "Sender "+sender+" is offline/not authenticated"
                                server.deInitConn(sock)
                    except:
                        # Error handling
                        print "Client (%s, %s) is offline" % addr
                        server.deInitConn(sock)
                        continue

        # Error handling
        # The signal send by the heartbeat alarm shouldn't disturb the select.select
        # This is to ensure that the signal is non-blocking
        except select.error,v:
            if v[0] != errno.EINTR:
                raise
            else:
                continue

    # If out of while 1 loop shut down server
    server.shutdown()
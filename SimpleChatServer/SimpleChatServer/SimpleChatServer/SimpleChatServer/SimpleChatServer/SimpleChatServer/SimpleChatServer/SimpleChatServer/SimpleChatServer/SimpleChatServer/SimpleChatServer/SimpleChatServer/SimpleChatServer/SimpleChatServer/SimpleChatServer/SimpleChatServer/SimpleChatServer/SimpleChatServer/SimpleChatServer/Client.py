import sys,select,socket,getpass
class Client:
    clientSocket = None         # Socket for connecting to server
    listenSocket = None         # Socket for listening for messages from server/ other users
    pvtHostSocket = None        # Socket for chatting privately with other users - p2p
    listenPort = None           # port number associated with listenSocket
    socketList = [sys.stdin]    # List of sockets to check and userinput
    bufferSize = 4096           # Receive buffer size
    name = None                 # username
    online = False              # is the client online
    host = None                 # server Ip
    port = None                 # server port number
    heartBeatInterval = 30      # Interval to send heartbeat messages to server
    privateMessageDB = {}       # Dictionary for storing IP and port for private chat - p2p

    # Method to set heartBeatInterval
    def setHeartBeat(self,heartBeat):
        self.heartBeatInterval = heartBeat


    # Method to connect to the chat server
    def connChatServ(self,host,port):
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clientSocket.settimeout(2)
        try :
            self.clientSocket.connect((host, port))
            self.socketList.append(self.clientSocket)
        except:
             print 'Unable to connect to ' + str(host) + '  on port' + str(port)
             sys.exit()


    # Method to connect to the host for private chat - p2p
    def connectToHost(self,host,port):
        self.pvtHostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.pvtHostSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.pvtHostSocket.settimeout(2)
        try:
            self.pvtHostSocket.connect((host, port))
            self.socketList.append(self.pvtHostSocket)
            return True
        # Error handling : if the host is not online at the IP and port number
        except:
            sys.stdout.write("User is not online at "+ host + " on "+ str(port)+"\n>")
            sys.stdout.write("Either Use 'getaddress <username>' to get the new address!\n>")
            sys.stdout.write("Or use offline messaging through serverh server using 'message <username> <msg>'\n")
            sys.stdout.flush()
            return False


    # Method to create listening socket
    def createListSocket(self):
        try:
            self.listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, msg:
            print 'Failed to create welcome socket. Error code : ' + str(msg[0]) + 'Error message : ' + msg[1]
            sys.exit()
        #Set options
        self.listenSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Bind the socket to port number not in use
        self.listenSocket.bind(('0.0.0.0', 0))
        # Save the port nubmer
        self.listenPort = self.listenSocket.getsockname()[1]
        #Listen on server socket
        self.listenSocket.listen(5)


    # Send messages through a socket
    def sendMsg(self,sock,message):
        try:
            sock.send(message)
        except:
            #connection is broken
            self.deInitConn(sock)


    # Receive messages from a socket
    def recvMsg(self,sock):
        try:
            data = sock.recv(self.bufferSize)
            return data
        except:
            #connection is broken
            self.deInitConn(sock)
            sys.exit()


    # De Init  TCP connection --> Non permanent TCP
    def deInitConn(self,sock):
        sock.close()
        self.socketList.remove(sock)


    # Prompt the user for username and password
    def promptUserPwd(self):
        username = raw_input("Username: ")
        password = getpass.getpass("Password: ")
        return (username,password)

    # Prompt only the password:]
    def promptPwd(self):
        password = getpass.getpass("Password: ")
        return password

    # Method to prompt username and password
    def getUsrPwd(self):
        username,password = self.promptUserPwd()
        # Create message to send to server "newUser,username,password,listenPort"
        usernamepwd = str("newUser"+','+username+','+password+','+str(self.listenPort))
        self.sendMsg(self.clientSocket,usernamepwd)

        # This loop runs until return is called.
        # Loop returns after the server has authenticated the user
        while 1:
            # Get the list of sockets that are readable
            readSockets,writeSockets,errorSockets = select.select(self.socketList , [], [])

            for sock in readSockets:
                if (sock == self.clientSocket):
                    data = self.recvMsg(sock)

                    if not data:
                        print '\nDisconnected from chat server'
                        sys.exit()

                    # If prompt , prompt the user for username and password
                    elif (data == "prompt"):
                        username,password = self.promptUserPwd()
                        # Convert into string to send it to the server "username,password"
                        usernamepwd = str(username+','+password)
                        self.sendMsg(sock,usernamepwd)

                    # User has entered the username correctly, but password is wrong
                    elif(data == "prompt_password"):
                        pwd = self.promptPwd()
                        self.sendMsg(sock,pwd)


                    # exit is sent from server if the user enters wrong password three times.
                    # exit the program
                    elif(data == "exit"):
                        sys.stdout.flush()
                        sys.exit()

                    # Any other message from server that is not "Authenticated"
                    else:
                        if("Authenticated" not in data):
                            sys.stdout.write(data)
                            sys.stdout.flush()
                            self.sendMsg(sock,"ok")

                        # If the message is "Authenticated", then save username and set online flag
                        else:
                            username = data[14:]
                            self.name = username
                            self.online = True
                            sys.stdout.write('>')
                            sys.stdout.flush()
                            # IMP : this is needed to continue the client application and
                            # exit the while 1 loop
                            return



    # Process command line instructions from the user
    def processCommand(self,command,msg):
        # Command to message another user
        if(command == "message"):
            if(len(msg.split(' ')) > 2 ):               # If the user enters only "message" avoid the out of index error
                receiver = msg.split()[1]               # Get receiver name
                message = msg.split(' ',2)[2]           # Get message
                self.connChatServ(self.host,self.port)
                final_message = str('forward'+','+self.name+','+receiver+','+message)
                self.sendMsg(self.clientSocket,final_message)
                self.deInitConn(self.clientSocket)
            else:
                # Error handle wrong format of command
                sys.stdout.write(">note:Command to send message is message <receiver> <msg>\n")
                sys.stdout.flush()
            return

        # Command to broadcast a message to all users online
        elif(command == "broadcast"):
            if(len(msg.split(' ')) > 1 ):
                message = msg.split(' ',1)[1]
                self.connChatServ(self.host,self.port)
                final_message = str(command+','+self.name+','+message)
                self.sendMsg(self.clientSocket,final_message)
                self.deInitConn(self.clientSocket)
            else:
                # Error handle wrong format of command
                sys.stdout.write(">note:Command to broadcast message is broadcast <msg>\n")
                sys.stdout.flush()
            return

        # Command to logout
        elif(command == "logout"):
            if(self.name):
                message = str("logout"+','+self.name)
            else:
                # If user presses control + c before getting authenticated
                message = str("logout"+','+"logout")
            self.online = False
            self.connChatServ(self.host,self.port)
            self.sendMsg(self.clientSocket,message)
            self.deInitConn(self.clientSocket)
            sys.stdout.flush()
            sys.exit()

        # Command to get a list of online users
        # Note : if any user has blocked this user, that user won't appear in the list
        elif(command == "online"):
            message = str("online"+','+self.name)
            self.connChatServ(self.host,self.port)
            self.sendMsg(self.clientSocket,message)
            self.deInitConn(self.clientSocket)
            return

        # Command to block a user
        # Note : the user can still message the blocked user
        # Blocking is not two way
        elif(command == "block"):
            if(len(msg.split(' ')) > 1):
                blockedUser = msg.split(' ')[1]
                message = str(command + ',' + self.name + ',' + blockedUser)
                self.connChatServ(self.host,self.port)
                self.sendMsg(self.clientSocket,message)
                self.deInitConn(self.clientSocket)
            else:
                # Error handle wrong format of command
                sys.stdout.write(">note:Command to block a user is block <username>\n")
                sys.stdout.flush()

        # Command to unblock a user
        elif(command == "unblock"):
            if(len(msg.split(' ')) > 1):
                unBlockedUser = msg.split(' ')[1]
                message = str(command + ',' + self.name +','+unBlockedUser)
                self.connChatServ(self.host,self.port)
                self.sendMsg(self.clientSocket,message)
                self.deInitConn(self.clientSocket)
            else:
                # Error handle wrong format of command
                sys.stdout.write(">note:Command to unblock a user is unblock <username>\n")
                sys.stdout.flush()

        # Command to get ip and port of a user. p2p chat
        elif(command == "getaddress"):
            if(len(msg.split(' '))> 1):
                user = msg.split(' ')[1]
                message = str(command+','+self.name + ','+user)
                self.connChatServ(self.host,self.port)
                self.sendMsg(self.clientSocket,message)
                self.deInitConn(self.clientSocket)
            else:
                # Error handle wrong format of command
                sys.stdout.write(">note: Command to get address of a user is getaddress <username>\n")
                sys.stdout.flush()

        # Command to start a private p2p chat with a user
        elif(command == "private"):
            if(len(msg.split(' ')) > 2):
                user = msg.split(' ')[1]
                message = msg.split(' ',2)[2]
                final_message = str(self.name+":"+message)
                # Check if the client already knows the IP and port of the user
                if(self.privateMessageDB.has_key(user)):
                    ip,port = self.privateMessageDB[user]
                    status = self.connectToHost(ip,port)
                    if status:
                        self.sendMsg(self.pvtHostSocket,final_message)
                        self.deInitConn(self.pvtHostSocket)
                else:
                    # If the user doesn't have the address, user can use getaddress command to get it
                    sys.stdout.write(">Request could not be processed.\n")
                    sys.stdout.write(">Use 'getaddress <username' to get the address of the user\n")
                    sys.stdout.flush()
            else:
                # Error handle wrong format of command
                sys.stdout.write(">note: Command to private message a user is private <username> <msg>\n")
                sys.stdout.flush()

        # Command to say yes to the private chat request
        elif(command == "consent"):
            if(len(msg.split(' ')) == 3):
                receiver = msg.split(' ')[1]
                answer = msg.split(' ')[2]
                message = str("private_answer,"+self.name+',' +\
                                                receiver + ',' + answer)
                self.connChatServ(self.host,self.port)
                self.sendMsg(self.clientSocket,message)
                self.deInitConn(self.clientSocket)
            else:
                sys.stdout.write("Please enter the correct format\n")
                sys.stdout.flush()


        # Default
        else:
            print "Command not recognized"
            return
















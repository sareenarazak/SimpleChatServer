import socket, select,sys,getpass,time
import User
class Server:

    socketConnList = []     # List of all sockets connected to the server
    serverSocket = None     # Server  socket
    connSocket = None       # Socket for connecting to clients, to forward messages
    welcomePort = 6001      # Port number of serverSocket
    bufferSize = 4096       # Receive buffer size
    blockTime = 60          # Time interval to block user for 3 wrong password trials
    heartBeatInterval = 35  # Time interval to check heartbeat of clients
    onlineConnList = []     # List of users that are online
    users = {}              # Dictionary of  usernames and passwords
    userObj = {}            # Dictionary of usernames and user objects


    # Init method to change buffer_size and welcome port
    def __init__(self, bufferSize, welcomePort):
        if bufferSize:
            self.bufferSize = bufferSize
        if welcomePort:
            self.welcomePort = welcomePort


    # Method to store username password in the users dictionary
    def storeUserCred(self):
        f = open('credentials.txt','r')
        data = f.readlines()
        for line in data:
            username,password  = line.split()
            self.users.update({username:password})
        f.close()


    # Method to create User objects for all the users
    # User class stores all the individual client related information
    def createUser(self):
        for key in self.users:
            user = User.User(key,0)
            self.userObj.update({key:user})


    # Method to create, initialize, listen on serverSocket
    def createInitServerSocket(self):
        try:
            self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error, msg:
            print 'Failed to create welcome socket. Error code : ' + str(msg[0]) + 'Error message : ' + msg[1]
            sys.exit()
        print 'Welcome socket created'
        #Set options
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #Bind the socket to localhost
        self.serverSocket.bind(("0.0.0.0", self.welcomePort))
        #Listen on server socket
        self.serverSocket.listen(5)


    # Method to append socket to the connection list of server
    def appendToConnList(self,sock):
        self.socketConnList.append(sock)


    # Method to remove socket from  connection list of server
    def removeFromConnList(self,sock):
        self.socketConnList.remove(sock)


    # User Authentication
    def authentClient(self,sock,data):
        # Receive username,password and listening port from client
        username = username = data.split(',')[1]
        password = data.split(',')[2]
        listenPort = data.split(',')[3]

        # If username is invalid keep prompting. User gets infinite number of trials for username
        while(self.userObj.has_key(username) == False):
            self.sendMsg(sock,"Invalid Username. Please try again.\n")
            signal = self.recvMsg(sock)
            if(signal == "ok"):
                self.sendMsg(sock,"prompt")
                data = self.recvMsg(sock)
                username,password = (item for item in data.split(','))

        # If username is valid, validate password
        else:
            currentUser = self.userObj[username]

            #check if user is blocked, and if the timer has expired
            if((currentUser.isBlocked) & ((time.time() - currentUser.time) <= self.blockTime)):
                self.sendMsg(sock,"Due to multiple login failures, your account has been blocked.\n")
                self.sendMsg(sock,"Please try again after sometime.\n")
                data = self.recvMsg(sock)
                if(data == "ok"):
                    self.sendMsg(sock,"exit")
                    return

            # If the user is blocked and the timer has expired , unblock user
            elif(currentUser.isBlocked):
                currentUser.setBlockedFlag(False)
                currentUser.setTime(0)

            # Update trial flag to one
            currentUser.setTrial(currentUser.trial + 1)

            # A user gets three trials to type correct password
            while((currentUser.trial < 3) & (self.users[username] != password)):
                self.sendMsg(sock,"Invalid Password. Please try again.\n")
                signal = self.recvMsg(sock)
                if(signal == "ok"):
                    self.sendMsg(sock,"prompt_password")
                    data = self.recvMsg(sock)
                    password = data.strip()
                    currentUser.setTrial(currentUser.trial + 1)

            # After the three trials, if the password is wrong, user is blocked for 60 seconds
            else:
                if(self.users[username] != password):
                    self.sendMsg(sock,'Invalid password. Your account has been blocked.\n')
                    self.sendMsg(sock,'Please try again after sometime.\n')
                    currentUser.setTime(time.time())
                    currentUser.setBlockedFlag(True)
                    currentUser.setTrial(0)
                    signal = self.recvMsg(sock)
                    if(signal == "ok"):
                        self.sendMsg(sock,"exit")

                # If the password is correct authenticate the user and return
                else:
                    # If a user under the same user name is active, logout the other user
                    if(currentUser.isOnline == True):
                        port = currentUser.listenPort
                        ipAddr   = currentUser.ipAddr
                        currentUser.ipAddr = None
                        currentUser.sock = None
                        currentUser.setAuthFlag(False)
                        currentUser.setOnlineFlag(False)
                        self.onlineConnList.remove(username)
                        self.connToClient(ipAddr,port)
                        self.sendMsg(self.connSocket,"logout_duplicate")
                        self.deInitConn(self.connSocket)

                    # Welcome the user to the server and update user info
                    self.sendMsg(sock,'Welcome to simple chat server!\n')
                    currentUser.setAuthFlag(True)
                    currentUser.setOnlineFlag(True)
                    self.onlineConnList.append(username)
                    currentUser.setTrial(0)
                    currentUser.setSock(sock)
                    currentUser.setIpAddr(sock.getpeername()[0])
                    currentUser.setListenPort(int(listenPort))
                    data = self.recvMsg(sock)
                    if(data == "ok"):
                        self.sendMsg(sock,"Authenticated "+ username)
                    print "Client (%s, %s) connected and authenticated" % sock.getpeername()
                    #Start the timer for checking heartbeat
                    self.userObj[username].setHeartBeatLast(time.time())


    # Method to connect to the client on listening port of the client
    def connToClient(self,host,port):
        self.connSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.appendToConnList(self.connSocket)
        self.connSocket.settimeout(2)
        try:
            self.connSocket.connect((host,port))
        except:
            print 'Unable to connect on port ' + str(port)
            self.removeFromConnList(self.connSocket)
            sys.exit()


    # Method to De Init the TCP connection --> non permanent TCP
    def deInitConn(self,sock):
        if(sock in self.socketConnList):
            self.socketConnList.remove(sock)
        sock.close()


    # Method to send messages to chat client
    def sendMsg(self,sock,message):
        try:
            sock.send(message)
        except:
            #connection is broken
            self.deInitConn(sock)


    # Method to receive messages from chat client
    def recvMsg(self,sock):
        try:
            data = sock.recv(self.bufferSize)
            return data
        except:
            #connection is broken
            self.deInitConn(sock)


    # Method to deliver offline messages to a client
    def deliverOfflineMsgs(self,receiver,messageList):
        port = self.userObj[receiver].listenPort
        ipAddr = self.userObj[receiver].ipAddr
        self.connToClient(ipAddr,port)
        print 'Connected on port to user %s at %s on port %s'% (receiver,ipAddr,str(port))
        final_message = "Offline messages: \n"
        for msg in messageList:
            final_message = final_message+msg
        self.sendMsg(self.connSocket,final_message)
        self.deInitConn(self.connSocket)
        # Clear the offline message buffer
        self.userObj[receiver].offlineMessages =[]


    # Method to forward chat messages to client
    def forwardMsg(self,receiver,message):
         port = self.userObj[receiver].listenPort
         ipAddr = self.userObj[receiver].ipAddr
         self.connToClient(ipAddr,port)
         if (message != "shutdown"):
            print 'Connected on port to user %s at %s on port %s'% (receiver,ipAddr,str(port))
         self.sendMsg(self.connSocket,message)
         self.deInitConn(self.connSocket)


    # Method to broadcast presence
    def presenceBroadcast(self,username):
        message = str("note:"+username+" is online!\n")
        self.broadCastNote(message,username)

    # Method to broadcast notifications to all users
    def broadCastNote(self,message,username):
        for user in self.onlineConnList:
            if(user!= username):
                if(user not in self.userObj[username].blockedList):
                    self.forwardMsg(user,message)


    # Method to broadcast to online users except the user that is sending
    def broadcastToOnUsrs(self,message,username):
        sendOnce = 0
        for user in self.onlineConnList:
            if(user!=username):
                if(username not in self.userObj[user].blockedList):
                    self.forwardMsg(user,message)
                elif(sendOnce == 0):
                    msg = 'Your message could not be delivered to some recipients\n'
                    sendOnce = 1
                    self.forwardMsg(username,msg)


    # Method to process requests from the user
    def processRequest(self,request,msg):
        # Request for forwarding message from one user to other
        if(request == "forward"):
            sender = msg.split(',')[1]
            receiver = msg.split(',')[2]
            message = msg.split(',',3)[3]
            if(self.userObj.has_key(sender) & self.userObj.has_key(receiver)):
                # Check if sender is in receiver's blocked list
                if(sender not in self.userObj[receiver].blockedList):
                    # If user is online forward the message
                    if(self.userObj[receiver].isOnline):
                        final_message = str(sender+":"+message)
                        self.forwardMsg(receiver,final_message)
                    # If user is offline store the messages for delivery when user comes online
                    else:
                        final_message = str(sender+":"+message)
                        self.userObj[receiver].addToOffLineMsgs(final_message)
                # Sender has blocked receiver. Intercept the message and do not forward
                else:
                    final_message = "Your message could not be" \
                                        "delivered\nas the recipient has blocked you\n"
                    self.forwardMsg(sender,final_message)

        # Request for broadcasting message to all users except the user that send it
        elif(request == "broadcast"):
            sender = msg.split(',')[1]
            message = msg.split(',',2)[2]
            if(self.userObj.has_key(sender)):
                final_message = str(sender+":"+message)
                self.broadcastToOnUsrs(final_message,sender)

        # Request for Logout
        elif(request == "logout"):
            user = msg.split(',')[1]
            if(user != "logout"):
                if(self.userObj.has_key(user)):
                    message = str("note:"+user+" is offline!\n")
                    # Send notification to all users
                    self.broadCastNote(message,user)
                    self.cleanUpUser(user)

        # Request for getting list of users that are online.
        # Only send the list of users that haven't blocked the requesting client
        elif(request == "online"):
            user = msg.split(',')[1]
            message = str("online")
            if(self.userObj.has_key(user)):
                for usr in self.onlineConnList:
                    if((usr != user) &(user not in self.userObj[usr].blockedList)):
                        message = str(message +','+ usr)
                if(user in self.onlineConnList):
                    self.forwardMsg(user,message)

        # Request for blocking the user
        elif(request == "block"):
            user = msg.split(',')[1]
            blockUser = msg.split(',')[2]
            blockedUser = blockUser.strip()
            if(self.userObj.has_key(user)):
                if(self.userObj.has_key(blockedUser)):
                    self.userObj[user].blockedList.append(blockedUser)
                    message = str("User "+ blockedUser + \
                                  " has been blocked\n")
                else:
                    message = "No such User in the system\n"
                self.forwardMsg(user,message)

        # Request to unblock user
        elif(request == "unblock"):
            user = msg.split(',')[1]
            unblocked = msg.split(',')[2]
            unBlockedUser = unblocked.strip()
            if(self.userObj.has_key(user)):
                if(unBlockedUser in self.userObj[user].blockedList):
                    self.userObj[user].blockedList.remove(unBlockedUser)
                    message = str("User "+ unBlockedUser + " is unblocked\n")
                else:
                    message = str("User " + unBlockedUser + \
                                " is not in the blocked list\n")
                self.forwardMsg(user,message)

        # Request to get IP address and port of a user
        elif(request == "getaddress"):
            sender = msg.split(',')[1]
            user = msg.split(',')[2].strip()
            if(self.userObj.has_key(user)):
                # Check if user is online
                if(self.userObj[user].isOnline):
                    # Check if requester has been blocked by the user
                    if(sender in self.userObj[user].blockedList):
                        message = "getaddress,blocked"
                        self.forwardMsg(sender,message)
                    else:
                        # Ask the user if they  want to talk to the requester
                        message = str("private_consent,"+sender)
                        self.forwardMsg(user,message)
                else:
                    message = "getaddress,offline"
                    self.forwardMsg(sender,message)

        # Reply from a user saying yes/no to private chat request:
        elif(request == "private_answer"):
            sender = msg.split(',')[1]
            receiver = msg.split(',')[2]
            answer = msg.split(',')[3].strip()
            if(self.userObj[receiver].isOnline):
                if(answer == "yes"):
                    message = str("getaddress,"+sender+','+\
                          str(self.userObj[sender].ipAddr) + ','+\
                          str(self.userObj[sender].listenPort))
                    self.forwardMsg(receiver,message)
                else:
                    message= str("getaddress,no")
                    self.forwardMsg(receiver,message)

        # Heartbeat message from user
        elif(request == "alive"):
            user = msg.split(',')[1]
            print "heartbeat msg of "+user+" received"
            if(user in self.onlineConnList):
                self.userObj[user].setHeartBeatLast(time.time())

        # Default case
        else:
            print "Command not recognized"


    # Method to clean up the user object after logging out
    def cleanUpUser(self,user):
        self.onlineConnList.remove(user)
        self.userObj[user].setSock(None)
        self.userObj[user].setAuthFlag(False)
        self.userObj[user].setOnlineFlag(False)
        self.userObj[user].setTime(0)
        self.userObj[user].setIpAddr(None)
        self.userObj[user].setListenPort(None)


    # Method to shut down the server
    def shutdown(self):
        if(self.onlineConnList):
            for user in self.onlineConnList:
                self.forwardMsg(user,"shutdown")
        self.serverSocket.close()
        del self




























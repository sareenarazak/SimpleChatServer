class User:

    name = None         # username of client
    sock = None         # socket

    # Init for User class
    def __init__(self, name,sock):
        if(name):
            self.name = name
        elif(sock):
            self.sock = sock

        self.isAuthenticated = False  # Flag to check if user is authenticated
        self.trial = 0                # Number of trials for entering password
        self.isOnline = False         # Flag to check if user is online
        self.time = 0                 # Time interval for which a user is blocked if wrong password is entered
        self.isBlocked = False        # Flag to check if user is blocked from logging in
        self.ipAddr = None            # Ip address
        self.listenPort = None        # Listening port number
        self.heartBeatLast = 0        # Time at which the last hearbeat message was received from user
        self.blockedList = []         # List of users this user has blocked
        self.offlineMessages  = []    # Messages that were sent ot this user, while offline


    def setName(self,name):
        self.name = name

    def setSock(self,sock):
        self.sock = sock

    def setAuthFlag(self,isAuth):
        self.isAuthenticated = isAuth

    def setTrial(self,trial):
        self.trial = trial

    def setOnlineFlag(self,isOnline):
        self.isOnline = isOnline

    def setTime(self,time):
        self.time = time

    def setBlockedFlag(self,isBlocked):
        self.isBlocked = isBlocked

    def setIpAddr(self,ipAddr):
        self.ipAddr = ipAddr

    def setListenPort(self,listenPort):
        self.listenPort = listenPort

    def setHeartBeatLast(self,heartBeat):
        if(heartBeat >= 0):
            self.heartBeatLast = heartBeat
        else:
            print "Heartbeat should be a positive number"

    def addToOffLineMsgs(self,msg):
        self.offlineMessages.append(msg)

    # Checks if the offline message buffer is empty
    def isOffLineMsg(self):
        if self.offlineMessages:
            return True
        else:
            return False







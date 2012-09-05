import socket, struct, os, traceback

debuggingMessage = None

def debugPrint(*args):
    if (debuggingMessage != None):
        debuggingMessage(' '.join(args)+'\n')

class ClientError(Exception):
    def __init__(self, error):
        self.value = str(error)
    def __str__(self):
        return self.value

class Opcode(object):
    """
    Class responsible for encoding and decoding TFTP datagrams
    """
    (OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR) = (1, 2, 3, 4, 5)
    @classmethod
    def interpret(self, rawData):
        """
        Return a dictionary containing the decoded components

        Keyword arguments:
        rawData -- a string containing the raw datagram recieved from the client

        Raise ClientError if the command/s is invalid
        """
        opcodeInterpreters = {
            self.OP_RRQ: self.__interpret_rwrq,
            self.OP_WRQ: self.__interpret_rwrq,
            self.OP_DATA: self.__interpret_data,
            self.OP_ACK: self.__interpret_ack,
            self.OP_ERROR: self.__interpret_error,
        }
        opcode, = struct.unpack("!H", rawData[:2])
        rawData = rawData[2:]
        if (opcode not in opcodeInterpreters): raise ClientError('UnimplementedOpcode')
        data = opcodeInterpreters[opcode](rawData)
        data['opcode'] = opcode
        return data
    @classmethod
    def __interpret_rwrq(self, rawData):
        dataSplit = rawData.split('\x00')
        if (len(dataSplit) != 3): raise ClientError('InvalidCommand')
        return {'filename': dataSplit[0], 'mode': dataSplit[1]}
    @classmethod
    def __interpret_data(self, rawData):
        try:
            block, = struct.unpack("!H", rawData[:2])
            data = rawData[2:]
        except struct.error: raise ClientError('InvalidCommand')
        return {'block': block, 'data':data}
    @classmethod
    def __interpret_ack(self, rawData):
        try: block, = struct.unpack('!h', rawData[:2])
        except struct.error: raise ClientError('InvalidCommand')
        return {'block': block}
    @classmethod
    def __interpret_error(self, rawData):
        try:
            block, = struct.unpack('!h', rawData[:2])
            msg = rawData[2:-1]
        except struct.error: raise ClientError('InvalidCommand')
        return {'errorCode': block, 'errorMessage': msg}
    @classmethod
    def build(self, opcode, *args):
        """
        Return a string containing an encoded datagram

        Keyword arguments:
        opcode -- the opcode to encode
        *args  -- the argument/s to the opcode (depends on what is being encoded)
                  See tftp standard. Arguments are given in order from left to right

        Raise ClientError if trying to encode an unimplemented opcode
        """
        opcodeBuilders = {
            self.OP_RRQ: self.__build_rwrq,
            self.OP_WRQ: self.__build_rwrq,
            self.OP_DATA: self.__build_data,
            self.OP_ACK: self.__build_ack,
            self.OP_ERROR: self.__build_error
        }
        if (opcode not in opcodeBuilders): raise ClientError('UnimplementedOpcode')
        data = opcodeBuilders[opcode](*args)
        return struct.pack('!h', opcode) + data
    @classmethod
    def __build_rwrq(self, filename, mode):
        return filename + '\x00' + mode + '\x00'
    @classmethod
    def __build_data(self, block, data):
        return struct.pack('!h', block) + data
    @classmethod
    def __build_ack(self, block):
        return struct.pack('!h', block)
    @classmethod
    def __build_error(self, code, msg):
        return struct.pack('!h', code) + msg + '\x00'

class Handler(object):
    """
    Base class representing a client.
    """
    init = False
    dataHandler = None
    dataRequest = None
    currentBlock = 0
    BLOCK_SIZE = 512
    # Housekeeping
    def finalize(self):
        """
        Called when finishing request. Override in subclass to clean up resources attained
        for request.
        """
        pass
    def __init__(self, serverSocket, client):
        self.serverSocket = serverSocket
        self.clientAddr = client
    def send(self, data):
        """
        Send data to client

        Keyword arguments:
        data -- the raw datagram to send

        """
        self.serverSocket.sendto(data, self.clientAddr)
    def handle(self, data):
        """
        Handle a packet from the client. Decode the packet and send to the right handlers.
        Return True if the whole request has been processed. Otherwise, return False if further
        packets are expected to be recieved from the client.

        Keyword arguments:
        data -- the raw packet

        Raise ClientError on weird requests from the client.
        """
        data = Opcode.interpret(data)
        if (self.init):
            return self.dataHandler(data)
        else:
            initializer = None
            if (data['opcode'] == Opcode.OP_RRQ):
                debugPrint(str(self.clientAddr), "requested to read", data['filename'])
                self.dataHandler = self.readHandler
                initializer = self.readRequest
            elif (data['opcode'] == Opcode.OP_WRQ):
                debugPrint(str(self.clientAddr), "requested to write", data['filename'])
                self.dataHandler = self.writeHandler
                initializer = self.writeRequest
            else:
                raise ClientError('ClientOutOfSync')
            self.init = True
            self.dataRequest = data
            return initializer()
    def __waitForAckThenFinish(self, data):
        if (data['opcode'] != Opcode.OP_ACK): raise ClientError('ClientOutOfSync')
        if (data['block'] != self.currentBlock): raise ClientError('ClientOutOfSync')
        return True
    def readHandler(self, data):
        """
        Handle read requests by calling readBlock.
        Return True if the whole request has been processed. Otherwise, return False if further
        packets are expected to be recieved from the client.

        Keyword arguments:
        data -- decoded packet
        """
        if (self.currentBlock != 0):
            if (data['opcode'] != Opcode.OP_ACK): raise ClientError('ClientOutOfSync')
            if (data['block'] != self.currentBlock): raise ClientError('ClientOutOfSync')
        self.currentBlock += 1
        blockData = self.readBlock()
        if (blockData != None):
            self.send(Opcode.build(Opcode.OP_DATA, self.currentBlock, blockData))
            if (len(blockData) < Handler.BLOCK_SIZE): self.dataHandler = self.__waitForAckThenFinish
            return False
        else:
            return True

    def writeHandler(self, data):
        """
        Handle write requests by calling writeBlock.
        Return True if the whole request has been processed. Otherwise, return False if further
        packets are expected to be recieved from the client.

        Keyword arguments:
        data -- decoded packet
        """
        if (data['opcode'] != Opcode.OP_DATA): raise ClientError('ClientOutOfSync')
        self.currentBlock = data['block']
        self.writeBlock(data['data'])
        self.send(Opcode.build(Opcode.OP_ACK, self.currentBlock))
        if (len(data['data']) < Handler.BLOCK_SIZE):
            return True
        else:
            return False

    def writeBlock(self, data):
        """
        Write a block of data. Current block number is stored in self.currentBlock. Multiply
        the block number by BLOCK_SIZE to get byte offset into content.
        Do not assume block numbers will increase with each call.

        You should override this method in a subclass.

        Keyword arguments:
        data -- raw data to write
        """
        pass
    def readBlock(self):
        """
        Read and return a block of data. Current block number is stored in self.currentBlock.
        Multiply the block number by BLOCK_SIZE to get byte offset into content.
        Do not assume block numbers will increase with each call.

        You should override this method in a subclass.
        """
        return ""

    def readRequest(self):
        """
        Prepare for a read request.
        Return True if the whole request has been processed. Otherwise, return False if further
        packets are expected to be recieved from the client.

        If this is overrided in a subclass, ensure that the overrided method calls its supermethod.
        """
        return self.readHandler(None)
    def writeRequest(self):
        """
        Prepare for a write request.
        Return True if the whole request has been processed. Otherwise, return False if further
        packets are expected to be recieved from the client.

        If this is overrided in a subclass, ensure that the overrided method calls its supermethod.
        """
        self.send(Opcode.build(Opcode.OP_ACK, 0))
        return False

class FileHandlerError(Exception):
    def __init__(self, error):
        self.value = str(error)
    def __str__(self):
        return self.value

class FileHandler(Handler):
    """
    Subclass of Handler which performs read and write requests on files in the current working
    directory.
    """
    file = None
    def finalize(self):
        if (self.file != None): self.file.close()
    def shouldFollowSymlinks(self):
        """
        Return whether symbolic links should be followed. Override to change from default
        """
        return False
    def getRealPath(self, path):
        """
        Return absolute pathname while also checking if the requested file is in the current
        working directory

        Keyword arguments:
        path -- the path to check and make absolute

        Raise FileHandlerError if the requested file is not under the current working directory
        """
        absPath = os.path.normcase(os.path.abspath(path))
        cwdPath = os.path.normcase(os.getcwd())
        if (not self.shouldFollowSymlinks): absPath = os.path.realpath(absPath)
        commonPath = os.path.commonprefix([cwdPath, absPath])
        if (os.path.normpath(commonPath) == cwdPath): return absPath
        else: raise FileHandlerError('AccessOutOfBounds')
    def readRequest(self):
        """
        Handle a read request by finding and opening the required files.
        """
        try:
            path = self.getRealPath(self.dataRequest['filename'])
            self.file = open(path, 'rb')
        except (FileHandlerError, IOError) as e:
            self.send(Opcode.build(Opcode.OP_ERROR, 0, "Unable to access file"))
            debugPrint(str(self.clientAddr), "was denied access to", self.dataRequest['filename'], str(e))
            return True
        debugPrint(str(self.clientAddr), "reading from", path)
        return Handler.readRequest(self)
    def writeRequest(self):
        """
        Handle a write request by finding and opening the required files.
        """
        try:
            path = self.getRealPath(self.dataRequest['filename'])
            self.file = open(path, 'wb')
        except (FileHandlerError, IOError) as e:
            self.send(Opcode.build(Opcode.OP_ERROR, 0, "Unable to modify file"))
            debugPrint(str(self.clientAddr), "was denied access to", self.dataRequest['filename'], str(e))
            return True
        debugPrint(str(self.clientAddr), "writing to", path)
        return Handler.writeRequest(self)
    def writeBlock(self, data):
        """
        Write a block to the opened file.

        Keyword arguments:
        data -- raw data to write

        """
        self.file.seek((self.currentBlock-1)*Handler.BLOCK_SIZE)
        return self.file.write(data)
    def readBlock(self):
        """
        Return a block from the opened file.
        """
        self.file.seek((self.currentBlock-1)*Handler.BLOCK_SIZE)
        return self.file.read(Handler.BLOCK_SIZE)

class Server(object):
    clientList = {}
    def __init__(self, address = ("0.0.0.0", 69), handerClass=Handler):
        """
        Initialize server.

        Keyword arguments:
        address -- a tuple containing (address, port) to bind to.
        handlerClass -- class used to handle client requests

        """
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,  socket.IPPROTO_UDP)
        self.serverSocket.bind(address)
        self.handlerClass = handerClass
    def serve(self):
        """
        Serve requests forever until a KeyboardInterrupt occurs
        """
        try:
            while True:
                data, client = self.serverSocket.recvfrom(516)
                if (client not in self.clientList):
                    debugPrint(str(client), "connected")
                    self.clientList[client] = self.handlerClass(self.serverSocket, client)
                try:
                    if (self.clientList[client].handle(data)):
                        self.clientList[client].finalize()
                        del self.clientList[client]
                        debugPrint(str(client), "disconnected successfully")
                except (ClientError, socket.error) as e:
                    self.clientList[client].finalize()
                    del self.clientList[client]
                    debugPrint(str(client), "disconnected due to client error", str(e))
                except KeyboardInterrupt:
                    raise
                except:
                    debugPrint(str(client), "threw unhandled exception")
                    self.serverSocket.sendto(Opcode.build(Opcode.OP_ERROR, 0, "Internal Server Error"), client)
                    del self.clientList[client]
                    traceback.print_exc()
                    debugPrint(str(client), "disconnected due to server error")
        except KeyboardInterrupt:
            self.finish()
    def finish():
        """
        Finish serving and clean up resources.
        """
        for client in clientList:
            client.finalize()
        self.serverSocket.close()

if __name__ == '__main__':
    """
    Command line arguments:
    python -m SimpleTftpServer [address [port]]

    Keyword arguments:
    address -- address to bind to
    port -- port to listen on

    """
    import sys
    debuggingMessage = sys.stderr.write
    bindAddr = '0.0.0.0'
    bindPort = 69
    if (len(sys.argv) > 1): bindAddr = sys.argv[1]
    if (len(sys.argv) > 2): bindPort = int(sys.argv[2])
    debugPrint("Starting TFTP server on", bindAddr+":"+str(bindPort))
    Server((bindAddr, bindPort), FileHandler).serve()
import socket
import threading
import sys 
import argparse
import time
import hashlib
import logging
import random

# used to enable debugging print statements
verbosity = 0

logging.basicConfig(filename="logs.log", format="%(message)s", filemode="a")
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
# USE: logger.info("Your message") to add a line in the log

# file hash function copied from https://www.programiz.com/python-programming/examples/hash-file
def hash_file(filename):
   """"This function returns the SHA-1 hash
   of the file passed into it"""

   # make a hash object
   h = hashlib.sha1()

   # open file for reading in binary mode
   with open(filename,'rb') as file:
       
       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)

   # return the hex representation of digest
   return h.hexdigest()

# Use sys.stdout.flush() after print statemtents

# function that frequently asks server for information regarding missing chunks
def find_missing_chunk(NAME, PATH, clientSocket, NUM_CHUNKS, chunks_owned):

    # dict containing info about missing chunks that are known and available for searching
    # format: { INDEX : (IP, PORT, HASH) }
    search_chunk = {}

    # first find missing chunks and append to search_chunk dictionary if chunk is known in P2P Tracker
    while len(chunks_owned) < NUM_CHUNKS:
        # go through each possible index
        for i in range(1, NUM_CHUNKS + 1):
            # check whether the chunk is already owned
            if (i not in chunks_owned):
                # send query to P2P Tracker for info regarding missing chunk
                cmd = f'WHERE_CHUNK,{i}'
                clientSocket.send(bytes(cmd, 'utf-8'))

                if (verbosity):
                    print(f'sent info request for chunk_{i}')

                # log action
                logger.info(f'{NAME},{cmd}')

                # get query response from P2P Tracker
                response = clientSocket.recv(1024)
                decoded_message = str(response, 'utf-8').split(',')

                if (decoded_message[0] == 'GET_CHUNK_FROM'):
                    # get a random user from the list of available ip's
                    # decoded message is an array of the form: [TYPE, INDEX, FILE_HASH, IP_1, PORT_1, IP_2, PORT_2, ...]
                    file_hash = decoded_message[2]
                    random_user = random.randrange(3, len(decoded_message), 2) # picks a random IP from avialable users
                    search_chunk[i] = (decoded_message[random_user], decoded_message[random_user + 1], file_hash) # random_user + 1 for access port
                elif (decoded_message[0] == 'CHUNK_LOCATION_UNKNOWN'):
                    print("Chunk location unknown")
                else:
                    print("Unkown response from server?")

        # find the missing chunks from peers
        for index in search_chunk.keys():

            # debug print call
            if (verbosity):
                print(f'chunks_owned: {chunks_owned}')
                print(f'search_chunk: {search_chunk}')

            # get ip and port from search chunk
            # userr info for each chunk is stored in a tuple (IP, PORT, HASH) as the value of the dict {INDEX: (IP, PORT, HASH)}
            (search_IP, search_PORT, file_hash) = search_chunk[index]

            # create a new socket for a TCP connection to other peer to receive the missing file chunk
            try:
                tempSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except:
                print("Failed to create socket for chunk request (i.e. tempSocket)")

            # connect to corresponding peer using IP and PORT provided
            try:
                print(f'Attempting connection to {search_IP} on port {search_PORT}')
                tempSocket.connect((search_IP, int(search_PORT)))
            except socket.error as err:
                print("Error connecting to peer socket for chunk requests")
                tempSocket.close()
                continue
            
            # create request string with proper format
            cmd = f'REQUEST_CHUNK,{index}'
            # log action
            logger.info(f'{NAME},{cmd},{search_IP},{search_PORT}')
            # send chunk request
            tempSocket.send(bytes(cmd, 'utf-8'))
            
            # debug print 
            if (verbosity):
                print('chunk request sent')

            # receive all the chunk data and store in a file
            with open(f'{PATH}/chunk_{index}', 'ab') as writer:
                data = tempSocket.recv(1024)
                while (data != b''):
                    if (verbosity):
                        print(f'received {len(data)} bytes of data')
                    writer.write(data)
                    data = tempSocket.recv(1024)

            # update P2P Tracker by sending a local chunk command
            cmd = f'LOCAL_CHUNKS,{index},{file_hash},{IP_ADDR},{MY_PORT}'
            clientSocket.send(bytes(cmd, 'utf-8'))

            # log action
            logger.info(f'{NAME},{cmd}')
            
            # close socket
            tempSocket.close()

            # update known chunks
            chunks_owned.append(index)
        
        # clear search_chunk
        search_chunk.clear()
        time.sleep(5)





if __name__== "__main__":
    # parse command line arguments
    parser = argparse.ArgumentParser(description="Starts a Client for the P2P File  \
                                     Transfer System")
    parser.add_argument("-folder", help="<my-folder-full-path>")
    parser.add_argument("-transfer_port", help="<transfer-port-num>")
    parser.add_argument("-name", help="<entity-name>")

    args = parser.parse_args()

    # HOST and PORT are needed to connect to P2PTracker++
    HOST = "localhost"
    PORT = 5100

    # MY_PORT is used for file transfers between clients
    MY_PORT = int(args.transfer_port)
    NAME = args.name
    PATH = args.folder

    # HOSTNAME and IP_ADDRESS
    MY_HOSTNAME = socket.gethostname()
    IP_ADDR = 'localhost'
    print(f'{MY_HOSTNAME}: {IP_ADDR}') 

    # initialize client sockets
    try:
        # first socket is to connect to P2P Tracker
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # second socket is to connect to peers for a file transfer
        peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print("Socket creation failed")
        sys.stdout.flush()

    # connect to P2PTracker++ server to start P2P File Transfers
    try:
        clientSocket.connect((HOST, PORT))
    except socket.error as err:
        print("Connection to server was unsuccesful")
        sys.stdout.flush()
    
    # array to store indexes of known chunks
    chunks_owned = []

    # send all chunk info to P2P Tracker
    # create file object
    with open(f'{PATH}/local_chunks.txt', "r") as reader:
        # read the first line
        chunk = reader.readline().strip('\n').split(',')

        # send each chunk to server
        # iterate until last line is found
        while(chunk[1] != 'LASTCHUNK'):

            filename = chunk[1].strip('\r')
            # calculate the hash of the file
            file_hash_value = hash_file(f'{PATH}/{filename}')

            # create fstring with proper LOCAL_CHUNK type format
            cmd = f'LOCAL_CHUNKS,{chunk[0]},{file_hash_value},{IP_ADDR},{MY_PORT}'
            
            # send each chunk to P2P Tracker
            clientSocket.send(bytes(cmd, 'utf-8'))

            # record known chunks in chunk info
            chunks_owned.append(int(chunk[0]))

            # log action
            log_text = f'{NAME},LOCAL_CHUNKS,{chunk[0]},{file_hash_value},{IP_ADDR},{MY_PORT}'
            logger.info(log_text)

            if (verbosity): 
                print(f'sent: {cmd}') # debug print statement

            # waits before sending next line to avoids overwhelming P2P server
            time.sleep(1)

            # move to next line containing next chunk or last line
            chunk = reader.readline().strip('\n').split(',')

        # total number of chunks over the entire file_set
        NUM_CHUNKS = int(chunk[0])

    # Start another thread that asks for the missing chunks to P2P Tracker
    searchThread = threading.Thread(target=find_missing_chunk, args=(NAME, PATH, clientSocket, NUM_CHUNKS, chunks_owned, ))
    searchThread.start()

    # bind peer socket to localhost IP and transfer port
    try:
        peerSocket.bind((IP_ADDR, MY_PORT))
    except:
        print("Socket binding failed")
        sys.stdout.flush()

    # start listening for incoming peers
    peerSocket.listen()
    if (verbosity):
        print(f'Stared listening to incoming peers on port {MY_PORT}. Accepting connections')

    while True:
        # accept incoming peer
        transmitSocket, peerAddress = peerSocket.accept()

        print(f'{peerAddress} has been accepted')

        # receive request command
        request = str(transmitSocket.recv(1024),'utf-8').split(',')

        # parse reqeust and send appropriate chunk/file
        if (request[0] == 'REQUEST_CHUNK'):
            with open(f'{PATH}/chunk_{request[1]}', 'rb') as reader:
                while True:
                    data = reader.read()
                    if (data == b''):
                        break
                    transmitSocket.send(data)

        if (verbosity):
            print('finished sending data')
        
        # terminate connection once file transfer is done
        transmitSocket.close()

    peerSocket.close()
    
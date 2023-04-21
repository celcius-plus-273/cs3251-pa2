import socket
import threading
import sys 
import argparse
import time
import hashlib
import logging

# used to enable debugging print statements
verbosity = 1

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
def find_missing_chunk():
    pass

if __name__== "__main__":
    # parse command line arguments
    parser = argparse.ArgumentParser(description="Starts a Client for the P2P File  \
                                     Transfer System")
    parser.add_argument("-folder", help="<my-folder-full-path>")
    parser.add_argument("-transfer_port", help="<transfer-port-num>")
    parser.add_argument("-name", help="<entity-name>")

    args = parser.parse_args()

    # HOST and PORT are needed to connect to P2PTracker++
    HOST = "127.0.0.1"
    PORT = 5100

    # MY_PORT is used for file transfers between clients
    MY_PORT = int(args.transfer_port)
    NAME = args.name
    PATH = args.folder

    # HOSTNAME and IP_ADDRESS
    MY_HOSTNAME = socket.gethostname()
    IP_ADDR = socket.gethostbyname(MY_HOSTNAME)
    print(f'{MY_HOSTNAME}: {IP_ADDR}') 

    # initialize client sockets
    try:
        # first socket is to connect to P2P Tracker
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # second socket is to connect to peers for a file transfer
        peerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.err as err:
        print("Socket creation failed")
        sys.stdout.flush()

    # connect to P2PTracker++ server to start P2P File Transfers
    try:
        clientSocket.connect((HOST, PORT))
    except socket.err as err:
        print("Connection to server was uunsuccesful")
        sys.stdout.flush()
    
    # dict to store information related to each chunk and where to find it
    # { INDEX : OWN or }
    CHUNKS_OWNED = 0 # number of chunks owned by this user
    chunk_info = {}

    # send all chunk info to P2P Tracker
    # create file object
    reader = open(f'{PATH}/local_chunks.txt', "rb")

    # read the first line
    chunk = reader.readline().decode().strip('\n').split(',')

    # send each chunk to server
    while(chunk[1] != 'LASTCHUNK'):

        filename = chunk[1].strip('\r')
        # calculate the hash of the file
        file_hash_value = hash_file(f'{PATH}/{filename}')
        
        # create fstring with proper LOCAL_CHUNK type format
        cmd = f'LOCAL_CHUNKS,{chunk[0]},{file_hash_value},{IP_ADDR},{MY_PORT}'
        
        # send each chunk to P2P Tracker
        clientSocket.send(bytes(cmd, 'utf-8')) 

        # log action
        log_text = f'{NAME},LOCAL_CHUNKS,{chunk[0]},{file_hash_value},{IP_ADDR},{MY_PORT}'
        logger.info(log_text)

        if (verbosity): 
            print(f'sent: {cmd}') # debug print statement

        # waits before sending next line to avoids overwhelming P2P server
        time.sleep(1)

        chunk = reader.readline().decode().strip('\n').split(',')

    # total number of chunks over the entire file_set
    NUM_CHUNKS = int(chunk[0])

    # bind peer socket to localhost IP and transfer port
    try:
        peerSocket.bind(('', MY_PORT))
    except socket.err as err:
        print("Socket binding failed")
        sys.stdout.flush()

    peerSocket.listen()

    while True:
        transmitSocket, peerAddress = peerSocket.accept()

    
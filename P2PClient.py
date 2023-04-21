import socket
import threading
import sys 
import argparse

# used to enable debugging print statements
verbosity = 1

# Use sys.stdout.flush() after print statemtents

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

    # send all chunk info to P2P Tracker
    # create file object
    reader = open(f'{PATH}/local_chunks.txt', "rb")

    # go to last line of file and find the number of chunks in the file
    # reader.seek(-9, 2)
    # try:
    #     while(reader.read(1) != b'\n'):
    #         reader.seek(-2, 1)
    # except err:
    #     reader.seek(0)
    #     print("Error finding last line of file")

    # NUM_CUNKS = int((reader.readline().decode()).split(',')[0])
    
    # read the first line
    chunk = reader.readline().decode().strip('\n').split(',')

    # send each chunk to server
    while(chunk[1] != 'LASTCHUNK'):
        # create fstring with proper LOCAL_CHUNK type format
        cmd = f'LOCAL_CHUNKS,{chunk[0]},{hash(chunk[1])},{IP_ADDR},{MY_PORT}\n'
        
        # send each chunk to P2P Tracker
        clientSocket.send(cmd.encode()) 

        if (verbosity): 
            print(f'sent: {cmd}') # debug print statement

        # wait for an ACK before sending next line
        # this avoids overwhelming P2P server
        while (clientSocket.recv(1024).decode() != 'ACK'):
            continue

        chunk = reader.readline().decode().strip('\n').split(',')

    # total number of chunks over the entire file_set
    NUM_CHUNKS = int(chunk[0])
    print(NUM_CHUNKS)

    # bind peer socket to localhost IP and transfer port
    try:
        peerSocket.bind(('', MY_PORT))
    except socket.err as err:
        print("Socket binding failed")
        sys.stdout.flush()

    
import socket
import threading
import sys 
import argparse

# used to enable debugging print statements
verbosity = 0

# Use sys.stdout.flush() after print statemtents

# thread for handling incoming messages from hosts
def user(clientSocket, checkList, chunkList, listLock):
    while True:
        # receives an incoming input from a user
        message = clientSocket.recv(1024).decode().strip('\n')
        if (message == ''):
            break
        
        if (verbosity):
            print(f'received: {message}')

        # ACK received message 
        clientSocket.send('ACK'.encode())

        # decodes the message according to its type (LOCAL_CHUNKS or WHERE_CHUNK)
        decoded_message = message.split(',')
        cmd = decoded_message[0]
        if (cmd == 'LOCAL_CHUNKS'):
            # message is in the format: <type>,<index>,<hash>,<ip>,<port>
            index = int(decoded_message[1])
            file_hash = decoded_message[2]
            user_ip = decoded_message[3]
            user_port = decoded_message[4]
        elif (cmd == 'WHERE_CHUNK'):
            # message is in the format: <type>,<index>
            index = int(decoded_message[1])
        else:
            print('Unknown command')

        # stores all incoming chunk info from LOCAL_CHUNK type commands
        if (cmd == 'LOCAL_CHUNKS'):
            # lock the list
            listLock.acquire()

            # update both lists
            if (index not in checkList.keys()):
                # create new chunk index in check list
                checkList[index] = [(file_hash, user_ip, user_port)]

            elif (index not in chunkList.keys()):
                # there's no two common chunk indexes yet
                # must check whether this new hash matches any of the old ones
                for (fh, ip, port) in checkList[index]:
                    # found a common hash!
                    if (fh == file_hash):
                        # add this common hash index entry to chunk list
                        chunkList[index] = [(fh, ip, port), (file_hash, user_ip, user_port)]
                # add to checklist regardless
                checkList[index].append((file_hash, user_ip, user_port))

            else:
                # index aready exists in chunk list
                # add user info if it mathces existing hash
                if (chunkList[index][0][0] == file_hash):
                    chunkList[index].append((file_hash, user_ip, user_port))
                
                # add to checkList regardless to keep as record
                checkList[index].append((file_hash, user_ip, user_port))

            # unlock the list
            listLock.release()

        print(f'checkList: {checkList}')
        print(f'chunkList: {chunkList}')
        
if __name__== "__main__":
    # no need of args? Add information about usage I guess?...
    parser = argparse.ArgumentParser(description="Initializes a Server Node for the \
                                     P2P File Transfer System")
    args = parser.parse_args()

    # initialize server socket
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except:
        print("Socket creation failed")
        sys.stdout.flush()

    # bind socket to localhost IP and Port 5100
    try:
        serverSocket.bind(('', 5100))
    except:
        print("Socket binding failed")
        sys.stdout.flush()
    
    # start istening for incoming connections
    serverSocket.listen(3)
    if (verbosity):
        print(f"Server started on port 5100. Accepting connections")

    # create check list
    # { KEY(CHUNK INDEX) : [(FILE_HASH_1, CLIENT_1_IP, CLIENT_1_PORT), (FILE_HASH_2, CLIENT_2_IP, CLIENT_2_PORT)] }
    # check list is a dictionary that holds chunk indexes as keys
    # every value in checkList corresponds to a list of all users containing the same chunk
    # each value (list of users) is organized as each user stored in a 3-tuple
    checkList = {}

    # create chunk list
    # chunkList follows a very similar format to checkList
    chunkList = {}
    
    # lock for check and chunk lists that ensures mutual exclusion between threads
    listLock = threading.Lock()

    # main loop that accepts incoming connections
    while True:
        clientSocket, clientAddress = serverSocket.accept()
        if (verbosity):
            print(f'{clientAddress} has been accepted')

        clientThread = threading.Thread(target=user, args=(clientSocket, checkList, chunkList, listLock, ))
        clientThread.start()

        if (verbosity):
            print('client thread started')
        

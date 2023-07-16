#!/usr/bin/env python3

import socket
import sys
import os, os.path
import time
import logging
import threading
import pickle

try:
    from .zbconst import *
except ImportError:
    from zbconst import *  

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class Usocket:
    
    def __init__(self , server_path=SOCKET_PATH) -> None:
        self.sock = None
        self.server_path = server_path
        self.connections=[]
        self.stop_threads=False

        
    def manage_connections(self,stop):
        while True:
            connection, client_address = self.sock.accept()
            _LOGGER.debug("New connection from %s Received" % client_address)
            self.connections.append(connection)
            if stop():
                self.connections=[]
                break
            

    def ustream_start (self):
        
        # Make sure the socket does not already exist
        try:
            os.unlink(self.server_path)
        except OSError:
            if os.path.exists(self.server_path):
                raise


        # Create a UDS socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        # Bind the socket to the port
        _LOGGER.debug( 'starting up on %s' % self.server_path ) 
        self.sock.bind(self.server_path)

        # Listen for incoming connections
        self.sock.listen(1)
        
        self.stop_threads = False
        wait_connections=threading.Thread(target = self.manage_connections, args=(lambda : self.stop_threads,))
        wait_connections.start()

        return True

 
    def close(self):
        #Todo verify if .close or .shoutdown
        self.stop_threads = True
        self.sock.close()
        
    
    def send_data_dstream (self,data:bytes):
        if self.sock is not None:            
            for k in self.connections:
                try:
                    k.sendall(data)
                except:
                    self.connections.remove(k)
                    
            return True
        else:
            return False
        
        
    def recv_data_dstream_async (self,observer,scheduler):
        rcv_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        timeout_start = time.time()
        connect_success = False
        while (time.time() < timeout_start + CLOSE_CLIENT_TIMEOUT) and not connect_success:
            try:
                rcv_sock.connect(self.server_path)
                connect_success = True
            except:
                time.sleep(0.5)
                
        while connect_success:
            try:
                data, server = rcv_sock.recvfrom(4096)
            except:
                observer.on_error(sys.exc_info()[0])
            finally:
                if data != None :
                    data_decoded=pickle.loads(data)
                    observer.on_next(data_decoded)

            
            
                    
        
        

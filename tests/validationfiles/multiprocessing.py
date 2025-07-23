
import multiprocessing
import time

def sender_process(connection, message):
    """
    This function runs in a separate process and sends a message
    through the provided Connection object.
    """
    print(f"Sender process: Sending '{message}'")
    connection.send(message) # Send the message through the connection
    connection.close() # Close the connection after sending
    print("Sender process: Message sent and connection closed.")

def receiver_process(connection):
    """
    This function runs in a separate process and receives data    
    """
    print("Receiver process: Waiting to receive data...")    
    received_data = connection.recv()
    print(f"Receiver process: Received '{received_data}'")
    connection.close() # Close the connection after receiving
    print("Receiver process: Connection closed.")

from multiprocessing import Process, Pipe



def f(conn):
    conn.send([42, None, 'hello'])
    conn.close()

def check_again():
    parent_conn, child_conn = Pipe()
    p = Process(target=f, args=(child_conn,))
    p.start()
    print(parent_conn.recv())   # prints "[42, None, 'hello']"
    p.join()

from multiprocessing.connection import Connection

def receive_data(conn: Connection):
    data = conn.recv()
    return data

def not_connection(obj):
    return obj.recv()
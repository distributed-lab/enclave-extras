#!/usr/bin/env python3
# ref: https://supervisord.org/events.html#example-event-listener-implementation
import os, sys, socket

TRANSPORT = os.getenv("TRANSPORT", "vsock")
CID = int(os.getenv("LOG_VSOCK_CID", "3"))
PORT = int(os.getenv("LOG_VSOCK_PORT", "8001"))
TCP_HOST = os.getenv("LOG_TCP_HOST", "127.0.0.1")
TCP_PORT = int(os.getenv("LOG_TCP_PORT", "1514"))

def connect():
    if TRANSPORT == "vsock":
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((CID, PORT))
        return s
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_HOST, TCP_PORT))
        return s

def write_stdout(s):
    # only eventlistener protocol messages may be sent to stdout
    sys.stdout.write(s)
    sys.stdout.flush()

def write_stderr(s):
    sys.stderr.write(s)
    sys.stderr.flush()

def main():
    sock = connect()
    
    while 1:
        # transition from ACKNOWLEDGED to READY
        write_stdout('READY\n')
        # read header line
        line = sys.stdin.readline()  # read header line from stdin
        headers = dict([ x.split(':') for x in line.split() ])
        # read event payload and send it to socket
        data = sys.stdin.read(int(headers['len']))
        sock.sendall(data.encode('utf-8', errors='ignore'))
        
        # transition from READY to ACKNOWLEDGED
        write_stdout('RESULT 2\nOK')

if __name__ == '__main__':
    main()

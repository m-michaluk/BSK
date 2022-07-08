from utils import get_first_flag, get_second_flag, get_third_flag
import socket

def main():
    PORT = 30000
    WELCOME_MESSAGE_SIZE = len("Welcome to the crypto task game!\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('cryptotask.var.tailcall.net', PORT))
    sock.settimeout(20)
    sock.recv(WELCOME_MESSAGE_SIZE)
    flag1 = get_first_flag(sock)
    print("flag 1:", flag1)
    flag2 = get_second_flag(sock)
    print("flag 2:", flag2)
    flag3 = get_third_flag(sock)
    print("flag 3:", flag3)

if __name__ == '__main__':
    main()
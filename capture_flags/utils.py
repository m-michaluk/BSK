from Crypto.Cipher import AES
import socket
import string
from Crypto.PublicKey import RSA


MENU='''
Select an option:
--- symmetric crypto section
 1) Get encrypted flag
 2) Change the secret key
 3) Encrypt something
--- asymmetric crypto section
 4) Register
 5) Login
 6) Get server public key
--- one-time-pad - proven secure!
 7) Get encrypted flag
'''
MENU_SIZE = len(MENU) + len("Choice: ")

# z pliku utils.py z kodu zadania
def read_until(s, suffix):
    res = b''
    while not res.endswith(suffix):
        # quite slow, but should be enough for us
        d = s.recv(1)
        if len(d) == 0:
            print("EOOFOFOFOF")
            raise EOFError()
        res += d
    return res

def read_bytes(sock, n):
    left = n
    while left != 0:
        res = sock.recv(left)
        left -= len(res)      

# Piersza flaga    
def get_encrypted_flag(sock):
    read_bytes(sock, MENU_SIZE)
    sock.send(b'1\n')       
    res = read_until(sock, b'\n')
    return res.decode()[0:-1]        

def get_encrypted_msg(sock, msg):
    read_bytes(sock, MENU_SIZE)
    sock.send(b'3\n')
    read_bytes(sock, len("Message to encrypt: "))
    sock.send((msg + "\n").encode())
    res = read_until(sock, b'\n')
    return res.decode()[0:-1]

def set_new_key(new_key, sock):
    read_bytes(sock, MENU_SIZE)
    sock.send(b'2\n')
    read_bytes(sock, len("New key (hex): "))
    sock.send((new_key+"\n").encode())
    read_bytes(sock, len("Done!\n"))

# który bajt flagi zgaduje
def guess_key(indx, original_key, plaintext, nonce, tag, ciphertext, all_pairs):
    tag = bytearray.fromhex(tag)
    nonce = bytearray.fromhex(nonce)
    ciphertext = bytearray.fromhex(ciphertext)
    for byte in all_pairs:
        original_key[2*indx] = byte[0]
        original_key[2*indx + 1] = byte[1]
        key = bytearray.fromhex(''.join(original_key))
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        try:
            data = cipher.decrypt_and_verify(ciphertext, tag)
            if data.hex() == plaintext:
                return original_key
        except:
            pass
    return

def get_first_flag(sock):
    PLAINTEXT = "00"

    hex_chars = "0123456789abcdef"
    all_pairs = [a + b for a in hex_chars for b in hex_chars]
    secret = b'0123456789abcdef'
    secret_hex = secret.hex()
    new_keys = [secret_hex[0:2*i+2] for i in range(len(secret_hex)//2 - 1)]
    encrypted_msgs = [] # wiadomości zaenkryptowane kluczami: oryginalny aes_key (którym zakodowano flagę), aes_key z wyzerowanymi 2 pierwszymi znakami, aes_key z wyzerowanymi 4 pierwszymi znakami itd.

    for new_key in new_keys:
        msg = get_encrypted_msg(sock, PLAINTEXT)
        encrypted_msgs.append(msg)
        set_new_key(new_key, sock)

    msg = get_encrypted_msg(sock, PLAINTEXT)
    encrypted_msgs.append(msg)    
    AES_KEY = list("00000000000000000000000000000000")

    for indx in reversed(range(len(AES_KEY)//2)):
        msg = encrypted_msgs[indx]
        i = msg.find(":")
        j = msg.rfind(":")
        ciphertext = msg[i+1:j]
        nonce = msg[0:i]
        tag = msg[j+1:]
        AES_KEY = guess_key(indx, AES_KEY, PLAINTEXT, nonce, tag, ciphertext, all_pairs)

    aes_key_original = bytearray.fromhex(''.join(AES_KEY))
    flag_encrypted = get_encrypted_flag(sock)

    i = flag_encrypted.find(":")
    j = flag_encrypted.rfind(":")
    ciphertext = bytearray.fromhex(flag_encrypted[i+1:j])
    nonce = bytearray.fromhex(flag_encrypted[0:i])
    tag = bytearray.fromhex(flag_encrypted[j+1:])
    cipher = AES.new(aes_key_original, AES.MODE_GCM, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data.decode()


# Druga flaga
def rsa_encrypt(key, message):
    key = RSA.import_key(key)
    return key._encrypt(message)

def get_public_key(sock):
    read_bytes(sock, MENU_SIZE)
    sock.send(b'6\n')
    public_key = ""
    line = ""
    while line != "-----END PUBLIC KEY-----\n":
        line = read_until(sock, b'\n').decode()
        public_key += line
    return public_key

def login_and_get_flag(sock, token):
    read_bytes(sock, MENU_SIZE)
    sock.send(b'5\n')
    read_bytes(sock, len("Your token: "))
    sock.send((str(token)+'\n').encode())
    read_bytes(sock, len("Hello flag!\nYour bio is: "))
    flag = read_until(sock, b'\n').decode()
    return flag[0:-1]

def get_second_flag(sock):
    public_key = get_public_key(sock)
    username = str("flag")
    token_int = int.from_bytes(username.encode(), byteorder='big')
    rsa_token = rsa_encrypt(public_key, token_int)
    flag = login_and_get_flag(sock, rsa_token)
    return flag

# Trzecia flaga
def get_ciphered_flag(sock):
    res = read_until(sock, b'\n')
    flag = res[17:-1].decode()
    return flag

def get_ciphered_flags(sock, n):
    ciphered_flag_list = []
    for i in range(n):
        sock.send(b'7\n')

    for i in range(n):
        read_bytes(sock, MENU_SIZE)
        ciphered_flag_list.append(get_ciphered_flag(sock))
    return ciphered_flag_list   


def get_third_flag(sock):
    CHARSET = string.ascii_letters + string.digits + '{}_'
    FLAG_SIZE = 34

    # Generujemy dużo zaszyfrowanych tekstów, znaki nie są szyfrowane równomiernie przez to, że 4 ostatnie znaki z CHARSETU losują się rzadziej jako klucz
    N = 100000
    flags_list = get_ciphered_flags(sock, N)
    counts = [[0]*len(CHARSET) for _ in range(FLAG_SIZE)] # i-ty wiersz to i-ty znak flagi, counts[i][j] to licznik ile razy dany znak był zaszyfrowany jako CHARSET[j]

    for flag in flags_list:
        for i in range(len(flag)):
            counts[i][CHARSET.index(flag[i])] += 1

    deciphered = ''
    for i in range(len(counts)):
        # dekoduję i-ty znak
        # szukam 4 najmniejszych występujących w segmencie cyklicznie
        sorted_counts = sorted(((v, i) for i, v in enumerate(counts[i])))
        rarest = []
        for i, (count, index) in enumerate(sorted_counts):
            if i == 4:
                break
            rarest.append(index)
        if max(rarest) - min(rarest) < 4:
            decrypted_indx = (min(rarest) + 4) %len(CHARSET)
        else:
            rarest = [(x + 4)%len(CHARSET) for x in rarest]
            decrypted_indx = min(rarest)
        deciphered += CHARSET[decrypted_indx]

    return deciphered    
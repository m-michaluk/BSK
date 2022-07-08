#!/usr/bin/env python3

import PIL
from PIL import Image
import sys

class FileWriter:
    def __init__(self, file):
        self.file = file
        self.str_buf = ''

    def write_bits(self, bits_str):
        self.str_buf = self.str_buf + bits_str

        if len(self.str_buf) >= 8:
            self.file.write(int(self.str_buf[0:8], 2).to_bytes(1, 'big'))
            self.str_buf = self.str_buf[8:]

def to_binary_str(num, bits_nr=None):
    binary = bin(num)[2:]
    if bits_nr == None:
        return binary
    if len(binary) < bits_nr:
        return (bits_nr - len(binary)) * "0" + binary
    else:
        return binary[-bits_nr:]

def decode(num, cum):
    if num >= cum:
        return num - cum
    else:
        return (256 - cum) + num  

def prev_pixel(pixels, i, j, w): # i -- kolumna, j -- wiersz
    if i == 0 and j == 0:
        return None
    if i == 0:
        return pixels[-1,j-1]
    return pixels[i-1, j]


def main():
    if len(sys.argv) != 3:
        sys.exit("Wrong number of arguments!")
        
    file_name = sys.argv[1]
    out_file_name = sys.argv[2]
    img = Image.open(file_name)
    converted_img = open(out_file_name, "wb")
    pixels = img.load()
    width, height = img.size
    # nagłówek - szerokość i wysokość, każde na 3 bajtach
    if width >= 2**24 or height >= 2**24:
        sys.exit("Picture too big to convert")
    converted_img.write(width.to_bytes(3, 'big'))
    converted_img.write(height.to_bytes(3, 'big'))

    write_helper = FileWriter(converted_img)
    b1, b2, b3 = (0, 0, 0)

    bound5 = 2**1
    bound4 = 2**3

    for i in range(height):
        for j in range(width): # j -- kolumna, i -- wiersz
            if (prev_pixel(pixels, j, i, height) != pixels[j, i]):                
                r, g, b = pixels[j, i]
                r = decode(r, b1)
                g = decode(g, b2)
                b = decode(b, b3)
                b1, b2, b3 = ((b1 + r)%256, (b2 + g)%256, (b3 + b)%256)

                m = max(r, g, b)
                if m < bound5:
                    write_helper.write_bits(to_binary_str(5, 3))
                    write_helper.write_bits(to_binary_str(r, 1))
                    write_helper.write_bits(to_binary_str(g, 1))
                    write_helper.write_bits(to_binary_str(b, 1))
                elif m < bound4:
                    write_helper.write_bits(to_binary_str(4, 3))
                    write_helper.write_bits(to_binary_str(r, 3))
                    write_helper.write_bits(to_binary_str(g, 3))
                    write_helper.write_bits(to_binary_str(b, 3))
                else:
                    write_helper.write_bits(to_binary_str(2, 3))
                    write_helper.write_bits(to_binary_str(r, 8))
                    write_helper.write_bits(to_binary_str(g, 8))
                    write_helper.write_bits(to_binary_str(b, 8))
    
            write_helper.write_bits(to_binary_str(6, 3))     

    write_helper.write_bits(to_binary_str(0, 8)) # żeby opróżnić str_buf, dodatkowe zera na końcu nie mają znaczenia
    converted_img.close()        

if __name__ == '__main__':
    main()
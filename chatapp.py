import socket
import string
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import *
# import tkinter.ttk as ttk
# import tkinter.ttk import *
from tkinter import IntVar
import sys
import time
import numpy as np
import math
import string
from tinyec import registry
from Cryptodome.Cipher import AES
import hashlib, secrets, binascii
# from ecies.utils import generate_key
# from ecies import decrypt
# from ecies import encrypt
# from tkinter import filedialog
# import base64, os
import customtkinter

customtkinter.set_default_color_theme("blue")

DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
FONT = ("Helvetica", 17)
FONT1 = ("Helvetica", 25)
WHITE = 'white'
SMALL_FONT = ("Helvetica", 13)
BUTTON_FONT = ("Helvetica", 13)

ciphertext5 = ""
plaintext6 = ""

root = tk.Tk()
root.geometry("500x250")
root.title("Secure chat App")
root.resizable(False, False)

# style =ttk.Style()

# style.configure('TButton', font=('calibri', 20, 'bold'),borderwidth='4')

# Changes will be reflected

# by the movement of mouse.
# style.map('TButton', foreground=[('active', '!disabled', 'green')],background=[('active', 'black')])


ciphertextbox = tk.StringVar()


class senderwindow:
    def __init__(self, master):
        top_frame = tk.Frame(root, width=500, height=80, bg=DARK_GREY)
        top_frame.grid(row=0, column=0, sticky=tk.NSEW)  # north,south, east,west

        middle_frame = tk.Frame(root, width=500, height=550, bg=MEDIUM_GREY)
        middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

        username_lable = tk.Label(top_frame, text="Sender", font=FONT1, bg=DARK_GREY, fg='white')
        username_lable.grid(sticky=tk.NSEW, padx=200)

        plaintext = tk.Label(middle_frame, text="Plaintext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor='w')
        plaintext.grid(row=2, column=0, sticky=tk.NSEW, pady=10)

        plaintextbox = tk.Entry(middle_frame, font=FONT, bg=MEDIUM_GREY, fg='white', )
        plaintextbox.grid(row=2, column=1, sticky=tk.NSEW, pady=10)

        key_lable = tk.Label(middle_frame, text="Key:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        key_lable.grid(row=3, column=0, sticky=tk.NSEW, pady=10)

        keybox = tk.Entry(middle_frame, font=FONT, bg=MEDIUM_GREY, fg='white', )
        keybox.grid(row=3, column=1, sticky=tk.NSEW, pady=10)

        technique_label = tk.Label(middle_frame, text="Technique:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        technique_label.grid(row=4, column=0, sticky=tk.NSEW, pady=10)

        options = ["Caesar cipher", "Monoalphabetic", "Polyalphabetic", "Hill cipher"
            , "Playfair", "OTP", "Rail fence", "Columnar"
            , "DES", "AES", "RC4", "RSA", "ECC"
            , "DH for key exchange", "Hashing (SHA) for integrity checking", "DSA for signature"]

        clicked = StringVar()  # use clicked.get() to get selected item by user

        clicked.set(options[0])

        techniquetype = tk.OptionMenu(middle_frame, clicked,
                                      *options)  # command = select and write select function sepreately
        techniquetype.grid(row=4, column=1, pady=10)

        encryptbutton = (tk.Button(middle_frame, text="Encrypt", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,
                                   command=lambda: self.Encryption(ciphertextbox, plaintextbox, keybox, clicked)))
        encryptbutton.grid(row=4, column=2, pady=10)  # style = "Tbutton"

        cipherlabel = tk.Label(middle_frame, text="Ciphertext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        cipherlabel.grid(row=5, column=0, sticky=tk.NSEW, pady=10)

        ciphertextbox = tk.Entry(middle_frame, font=FONT, bg=MEDIUM_GREY, fg='white', )
        ciphertextbox.grid(row=5, column=1, sticky=tk.NSEW, pady=10)

        sendbutton = (tk.Button(middle_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,
                                command=lambda: self.receiver(ciphertextbox)))
        sendbutton.grid(row=5, column=2, padx=20, pady=10)

    def key_matrix_generaftion(key):
        atoz = string.ascii_lowercase.replace('j', '.')

        key_matrix = ['' for i in range(5)]

        i = 0
        j = 0

        for c in key:
            if c in atoz:
                if c in atoz:
                    key_matrix[i] += c
                    atoz = atoz.replace(c, '.')

                    j += 1
                    if j > 4:
                        i += 1
                        j = 0

        for c in atoz:
            if c != '.':
                key_matrix[i] += c

                j += 1
                if j > 4:
                    i += 1
                    j = 0

        return key_matrix

    def Encryption(self, ciphert6, plaintt, keyt, clit):

        plaintt1 = plaintt.get()
        plaintt1 = plaintt1.lower()
        keyt1 = keyt.get()
        # keyt1 = keyt1.lower()
        clit1 = clit.get()

        if clit1 == "Caesar cipher":
            shift = int(keyt1)
            alphabet = string.ascii_lowercase
            shifted = alphabet[shift:] + alphabet[:shift]
            table = str.maketrans(alphabet, shifted)

            encrypted1 = plaintt1.translate(table)
            ciphert6.insert(0, encrypted1)




        elif clit1 == "Monoalphabetic":
            cipher2 = ""
            # key = zebraistpdcfghjklmnoquvwxy
            # key will replace a(of plaintext) to z, b to e and c to b etc
            for c in plaintt1:
                if c in string.ascii_lowercase:
                    index = ord(c) - ord('a')
                    cipher2 = cipher2 + keyt1[index]
                else:
                    cipher2 = cipher2 + c

            ciphert6.insert(0, cipher2)

        elif clit1 == "Polyalphabetic":
            alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                        't', 'u', 'v', 'w', 'x', 'y', 'z']
            # example key will be like "lemon"
            keyt1 = keyt1 * len(plaintt1)

            cypherText = ''

            count = 0

            for letter in plaintt1:
                if letter in string.ascii_lowercase:

                    shift = ord(keyt1[count]) - ord('a')
                    cypherLetter = chr((ord(letter) - ord('a') + shift) % 26 + ord('a'))
                    cypherText = cypherText + cypherLetter
                    count = (count + 1) % len(keyt1)

                else:
                    cypherText = cypherText + letter

            ciphert6.insert(0, cypherText)

        elif clit1 == "Hill cipher":
            # plain text has to be even number otherwise just write x at the end
            # Because it works on 2x1 matrix

            plaintt1 = plaintt1.upper()
            plaintt1 = plaintt1.replace(" ", "")

            # if message length is odd number, append 0 at the end
            len_chk = 0
            if len(plaintt1) % 2 != 0:
                plaintt1 += "0"
                len_chk = 1

            # plaintt1 to matrices
            row = 2
            col = int(len(plaintt1) / 2)
            plaintt12d = np.zeros((row, col), dtype=int)

            itr1 = 0
            itr2 = 0
            for i in range(len(plaintt1)):
                if i % 2 == 0:
                    plaintt12d[0][itr1] = int(ord(plaintt1[i]) - 65)
                    itr1 += 1
                else:
                    plaintt12d[1][itr2] = int(ord(plaintt1[i]) - 65)
                    itr2 += 1
            # for

            # keyt1 = input("Enter 4 letter Key String: ").upper()
            keyt1 = keyt1.replace(" ", "")

            # key to 2x2
            key2d = np.zeros((2, 2), dtype=int)
            itr3 = 0
            for i in range(2):
                for j in range(2):
                    key2d[i][j] = ord(keyt1[itr3]) - 65
                    itr3 += 1

            # checking validity of the key
            # finding determinant
            deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
            deter = deter % 26

            # finding multiplicative inverse
            mul_inv = -1
            for i in range(26):
                temp_inv = deter * i
                if temp_inv % 26 == 1:
                    mul_inv = i
                    break
                else:
                    continue
            # for

            if mul_inv == -1:
                print("Invalid key")
                sys.exit()
            # if

            encryp_text = ""
            itr_count = int(len(plaintt1) / 2)
            if len_chk == 0:
                for i in range(itr_count):
                    temp1 = plaintt12d[0][i] * key2d[0][0] + plaintt12d[1][i] * key2d[0][1]
                    encryp_text += chr((temp1 % 26) + 65)
                    temp2 = plaintt12d[0][i] * key2d[1][0] + plaintt12d[1][i] * key2d[1][1]
                    encryp_text += chr((temp2 % 26) + 65)
                # for
            else:
                for i in range(itr_count - 1):
                    temp1 = plaintt12d[0][i] * key2d[0][0] + plaintt12d[1][i] * key2d[0][1]
                    encryp_text += chr((temp1 % 26) + 65)
                    temp2 = plaintt12d[0][i] * key2d[1][0] + plaintt12d[1][i] * key2d[1][1]
                    encryp_text += chr((temp2 % 26) + 65)
                # for
            # if else

            ciphert6.insert(0, encryp_text)

        elif clit1 == "Playfair":

            # key will be secret
            def create_matrix(key):
                key = key.upper()
                matrix = [[0 for i in range(5)] for j in range(5)]
                letters_added = []
                row = 0
                col = 0
                # add the key to the matrix
                for letter in key:
                    if letter not in letters_added:
                        matrix[row][col] = letter
                        letters_added.append(letter)
                    else:
                        continue
                    if (col == 4):
                        col = 0
                        row += 1
                    else:
                        col += 1
                # Add the rest of the alphabet to the matrix
                # A=65 ... Z=90
                for letter in range(65, 91):
                    if letter == 74:  # I/J are in the same position
                        continue
                    if chr(letter) not in letters_added:  # Do not add repeated letters
                        letters_added.append(chr(letter))

                # print (len(letters_added), letters_added)
                index = 0
                for i in range(5):
                    for j in range(5):
                        matrix[i][j] = letters_added[index]
                        index += 1
                return matrix

            # Add fillers if the same letter is in a pair
            def separate_same_letters(message):
                index = 0
                while (index < len(message)):
                    l1 = message[index]
                    if index == len(message) - 1:
                        message = message + 'X'
                        index += 2
                        continue
                    l2 = message[index + 1]
                    if l1 == l2:
                        message = message[:index + 1] + "X" + message[index + 1:]
                    index += 2
                return message

            # Return the index of a letter in the matrix
            # This will be used to know what rule (1-4) to apply
            def indexOf(letter, matrix):
                for i in range(5):
                    try:
                        index = matrix[i].index(letter)
                        return (i, index)
                    except:
                        continue

            # Implementation of the playfair cipher
            # If encrypt=True the method will encrypt the message
            # otherwise the method will decrypt

            message = plaintt1
            key = keyt1
            inc = 1

            def playfair(key, message, encrypt=True):
                inc = 1
                if encrypt == False:
                    inc = -1
                matrix = create_matrix(key)
                message = message.upper()
                message = message.replace(' ', '')
                message = separate_same_letters(message)
                cipher_text = ''
                for (l1, l2) in zip(message[0::2], message[1::2]):
                    row1, col1 = indexOf(l1, matrix)
                    row2, col2 = indexOf(l2, matrix)
                    if row1 == row2:  # Rule 2, the letters are in the same row
                        cipher_text += matrix[row1][(col1 + inc) % 5] + matrix[row2][(col2 + inc) % 5]
                    elif col1 == col2:  # Rule 3, the letters are in the same column
                        cipher_text += matrix[(row1 + inc) % 5][col1] + matrix[(row2 + inc) % 5][col2]
                    else:  # Rule 4, the letters are in a different row and column
                        cipher_text += matrix[row1][col2] + matrix[row2][col1]

                ciphert6.insert(0, cipher_text)

            print(playfair(keyt1, plaintt1))

        elif clit1 == "Columnar":
            cipher8 = ""

            # track key indices
            k_indx = 0

            msg_len = float(len(plaintt1))
            msg_lst = list(plaintt1)
            key_lst = sorted(list(keyt1))

            # calculate column of the matrix
            col = len(keyt1)

            # calculate maximum row of the matrix
            row = int(math.ceil(msg_len / col))

            # add the padding character '_' in empty
            # the empty cell of the matix
            fill_null = int((row * col) - msg_len)
            msg_lst.extend('_' * fill_null)

            # create Matrix and insert message and
            # padding characters row-wise
            matrix = [msg_lst[i: i + col]
                      for i in range(0, len(msg_lst), col)]

            # read matrix column-wise using key
            for _ in range(col):
                curr_idx = keyt1.index(key_lst[k_indx])
                cipher8 += ''.join([row[curr_idx]
                                    for row in matrix])
                k_indx += 1

            ciphert6.insert(0, cipher8)

        elif clit1 == "DES":
            # pt = "123456ABCD132536"
            # key = "AABB09182736CCDD"

            # Hexadecimal to binary conversion

            def hex2bin(s):
                mp = {'0': "0000",
                      '1': "0001",
                      '2': "0010",
                      '3': "0011",
                      '4': "0100",
                      '5': "0101",
                      '6': "0110",
                      '7': "0111",
                      '8': "1000",
                      '9': "1001",
                      'a': "1010",
                      'b': "1011",
                      'c': "1100",
                      'd': "1101",
                      'e': "1110",
                      'f': "1111"}
                bin = ""
                for i in range(len(s)):
                    bin = bin + mp[s[i]]
                return bin

            # Binary to  hexadecimal conversion

            def bin2hex(s):
                mp = {"0000": '0',
                      "0001": '1',
                      "0010": '2',
                      "0011": '3',
                      "0100": '4',
                      "0101": '5',
                      "0110": '6',
                      "0111": '7',
                      "1000": '8',
                      "1001": '9',
                      "1010": 'a',
                      "1011": 'b',
                      "1100": 'c',
                      "1101": 'd',
                      "1110": 'e',
                      "1111": 'f'}
                hex = ""
                for i in range(0, len(s), 4):
                    ch = ""
                    ch = ch + s[i]
                    ch = ch + s[i + 1]
                    ch = ch + s[i + 2]
                    ch = ch + s[i + 3]
                    hex = hex + mp[ch]

                return hex

            # Binary to decimal conversion

            def bin2dec(binary):

                binary1 = binary
                decimal, i, n = 0, 0, 0
                while (binary != 0):
                    dec = binary % 10
                    decimal = decimal + dec * pow(2, i)
                    binary = binary // 10
                    i += 1
                return decimal

            # Decimal to  binary conversion

            def dec2bin(num):
                res = bin(num).replace("0b", "")
                if (len(res) % 4 != 0):
                    div = len(res) / 4
                    div = int(div)
                    counter = (4 * (div + 1)) - len(res)
                    for i in range(0, counter):
                        res = '0' + res
                return res

            # Permute function to rearrange the bits

            def permute(k, arr, n):
                permutation = ""
                for i in range(0, n):
                    permutation = permutation + k[arr[i] - 1]
                return permutation

            # shifting the bits towards left by nth shifts

            def shift_left(k, nth_shifts):
                s = ""
                for i in range(nth_shifts):
                    for j in range(1, len(k)):
                        s = s + k[j]
                    s = s + k[0]
                    k = s
                    s = ""
                return k

            # calculating xow of two strings of binary number a and b

            def xor(a, b):
                ans = ""
                for i in range(len(a)):
                    if a[i] == b[i]:
                        ans = ans + "0"
                    else:
                        ans = ans + "1"
                return ans

            # Table of Position of 64 bits at initial level: Initial Permutation Table
            initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                            60, 52, 44, 36, 28, 20, 12, 4,
                            62, 54, 46, 38, 30, 22, 14, 6,
                            64, 56, 48, 40, 32, 24, 16, 8,
                            57, 49, 41, 33, 25, 17, 9, 1,
                            59, 51, 43, 35, 27, 19, 11, 3,
                            61, 53, 45, 37, 29, 21, 13, 5,
                            63, 55, 47, 39, 31, 23, 15, 7]

            # Expansion D-box Table
            exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
                     6, 7, 8, 9, 8, 9, 10, 11,
                     12, 13, 12, 13, 14, 15, 16, 17,
                     16, 17, 18, 19, 20, 21, 20, 21,
                     22, 23, 24, 25, 24, 25, 26, 27,
                     28, 29, 28, 29, 30, 31, 32, 1]

            # Straight Permutation Table
            per = [16, 7, 20, 21,
                   29, 12, 28, 17,
                   1, 15, 23, 26,
                   5, 18, 31, 10,
                   2, 8, 24, 14,
                   32, 27, 3, 9,
                   19, 13, 30, 6,
                   22, 11, 4, 25]

            # S-box Table
            sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

                    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

                    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

                    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

                    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

                    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

                    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

                    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

            # Final Permutation Table
            final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                          39, 7, 47, 15, 55, 23, 63, 31,
                          38, 6, 46, 14, 54, 22, 62, 30,
                          37, 5, 45, 13, 53, 21, 61, 29,
                          36, 4, 44, 12, 52, 20, 60, 28,
                          35, 3, 43, 11, 51, 19, 59, 27,
                          34, 2, 42, 10, 50, 18, 58, 26,
                          33, 1, 41, 9, 49, 17, 57, 25]

            def encrypt(plaintt1, rkb, rk):
                plaintt1 = hex2bin(plaintt1)

                # Initial Permutation
                plaintt1 = permute(plaintt1, initial_perm, 64)
                # print("After initial permutation", bin2hex(pt))

                # Splitting
                left = plaintt1[0:32]
                right = plaintt1[32:64]
                for i in range(0, 16):
                    # Expansion D-box: Expanding the 32 bits data into 48 bits
                    right_expanded = permute(right, exp_d, 48)

                    # XOR RoundKey[i] and right_expanded
                    xor_x = xor(right_expanded, rkb[i])

                    # S-boxex: substituting the value from s-box table by calculating row and column
                    sbox_str = ""
                    for j in range(0, 8):
                        row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                        col = bin2dec(
                            int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                        val = sbox[j][row][col]
                        sbox_str = sbox_str + dec2bin(val)

                    # Straight D-box: After substituting rearranging the bits
                    sbox_str = permute(sbox_str, per, 32)

                    # XOR left and sbox_str
                    result = xor(left, sbox_str)
                    left = result

                    # Swapper
                    if (i != 15):
                        left, right = right, left
                # print("Round ", i + 1, " ", bin2hex(left),
                # " ", bin2hex(right), " ", rk[i])

                # Combination
                combine = left + right

                # Final permutation: final rearranging of bits to get cipher text
                cipher_text = permute(combine, final_perm, 64)
                return cipher_text

            # Key generation
            # --hex to binary
            keyt1 = hex2bin(keyt1)

            # --parity bit drop table
            keyp = [57, 49, 41, 33, 25, 17, 9,
                    1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27,
                    19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12, 4]

            # getting 56 bit key from 64 bit using the parity bits
            keyt1 = permute(keyt1, keyp, 56)

            # Number of bit shifts
            shift_table = [1, 1, 2, 2,
                           2, 2, 2, 2,
                           1, 2, 2, 2,
                           2, 2, 2, 1]

            # Key- Compression Table : Compression of key from 56 bits to 48 bits
            key_comp = [14, 17, 11, 24, 1, 5,
                        3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8,
                        16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32]

            # Splitting
            left = keyt1[0:28]  # rkb for RoundKeys in binary
            right = keyt1[28:56]  # rk for RoundKeys in hexadecimal

            rkb = []
            rk = []
            for i in range(0, 16):
                # Shifting the bits by nth shifts by checking from shift table
                left = shift_left(left, shift_table[i])
                right = shift_left(right, shift_table[i])

                # Combination of left and right string
                combine_str = left + right

                # Compression of key from 56 to 48 bits
                round_key = permute(combine_str, key_comp, 48)

                rkb.append(round_key)
                rk.append(bin2hex(round_key))

            # ("Encryption")
            cipher_text = bin2hex(encrypt(plaintt1, rkb, rk))

            ciphert6.insert(0, cipher_text)

        elif clit1 == "ECC":
           pass

    def receiver(self, ciphertextbook):
        root1 = Toplevel(root)
        root1.geometry("500x250")
        root1.title("Secure chat App")
        root1.resizable(False, False)

        ciphertext = ciphertextbook.get()
        top_frame1 = tk.Frame(root1, width=500, height=80, bg=DARK_GREY)
        top_frame1.grid(row=0, column=0, sticky=tk.NSEW)  # north,south, east,west

        middle_frame1 = tk.Frame(root1, width=500, height=550, bg=MEDIUM_GREY)
        middle_frame1.grid(row=1, column=0, sticky=tk.NSEW)

        username_lable1 = tk.Label(top_frame1, text="Receiver", font=FONT1, bg=DARK_GREY, fg='white')
        username_lable1.grid(sticky=tk.NSEW, padx=200)

        ciphertext1 = tk.Label(middle_frame1, text="Ciphertext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor='w')
        ciphertext1.grid(row=2, column=0, sticky=tk.NSEW, pady=10)
        # print(ciphertext)
        # g = ciphertext5.insert(0,ciphertextbox)
        # ciphertext = tk.StringVar()
        ciphertextbox1 = tk.Entry(middle_frame1, width=20, font=FONT, bg=MEDIUM_GREY, fg='white', borderwidth=1,
                                  relief="groove", )
        ciphertextbox1.grid(row=2, column=1, sticky=tk.NSEW, pady=10)
        # ciphertextbox1 = ciphertextbox1.insert(0, ciphertext)
        # b = ciphertextbox1["text"]

        key_lable1 = tk.Label(middle_frame1, text="Key:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        key_lable1.grid(row=3, column=0, sticky=tk.NSEW, pady=10)

        keybox1 = tk.Entry(middle_frame1, font=FONT, bg=MEDIUM_GREY, fg='white', )
        keybox1.grid(row=3, column=1, sticky=tk.NSEW, pady=10)

        technique_label1 = tk.Label(middle_frame1, text="Technique:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        technique_label1.grid(row=4, column=0, sticky=tk.NSEW, pady=10)

        options = ["Caesar cipher", "Monoalphabetic", "Polyalphabetic", "Hill cipher"
            , "Playfair", "OTP", "Rail fence", "Columnar"
            , "DES", "AES", "RC4", "RSA", "ECC"
            , "DH for key exchange", "Hashing (SHA) for integrity checking", "DSA for signature"]

        clicked = StringVar()  # use clicked.get() to get selected item by user

        clicked.set(options[0])

        techniquetype1 = tk.OptionMenu(middle_frame1, clicked,
                                       *options)  # command = select and write select function sepreately
        techniquetype1.grid(row=4, column=1, pady=8)

        techniquebutton1 = (tk.Button(middle_frame1, text="Decrypt", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,
                                      command=lambda: self.Decryption(plaintextbox1, ciphertextbox1, keybox1, clicked)))
        techniquebutton1.grid(row=4, column=2, pady=10)

        plainlabel1 = tk.Label(middle_frame1, text="Plaintext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        plainlabel1.grid(row=5, column=0, sticky=tk.NSEW, pady=10)

        plaintextbox1 = tk.Entry(middle_frame1, font=FONT, bg=MEDIUM_GREY, fg='white', )
        plaintextbox1.grid(row=5, column=1, sticky=tk.NSEW, pady=10)

    def Decryption(self, plaint6, ciphert2, keyt2, clit2):
        ciphert3 = ciphert2.get()  # "elq pezaz tbi" #
        # ciphert3 = ciphert2.lower()
        keyt3 = keyt2.get()
        keyt3 = keyt3.lower()
        clit3 = clit2.get()

        if clit3 == "Caesar cipher":
            keyt3 = int(keyt3)
            # output_text = ""
            # plaintt3 = ciphert3.lower()
            ciphert3.lower()
            decryptstring = ""
            for i in ciphert3:
                charvalue1 = ord(i) - keyt3
                if (charvalue1 < 97):
                    charvalue = ord('z') - (96 - charvalue1)
                    decryptstring += chr(charvalue1)
                else:
                    decryptstring += chr(charvalue1)
            plaint6.insert(0, decryptstring)

        elif clit3 == "Monoalphabetic":
            # key3t = "zebraistpdcfghjklmnoquywxy"
            plaintext3 = ""
            for c in ciphert3:
                if c in string.ascii_lowercase:
                    index = keyt3.find(c)
                    plaintext3 += chr(index + ord('a'))
                else:
                    plaintext3 = plaintext3 + c
            plaint6.insert(0, plaintext3)

        elif clit3 == "Polyalphabetic":
            count = 0
            ciphert4 = ''
            for c in ciphert3:
                if c in string.ascii_lowercase:

                    shift = ord(keyt3[count]) - ord('a')
                    cypherLetter1 = ord(c) - ord('a') - shift
                    if cypherLetter1 < 0:
                        cypherLetter1 = cypherLetter1 + 26

                    cypherText1 = chr(cypherLetter1 + ord('a'))

                    ciphert4 = ciphert4 + cypherText1
                    count = (count + 1) % len(keyt3)

                else:
                    ciphert4 = ciphert4 + c

            plaint6.insert(0, ciphert4)

        elif clit3 == "Hill cipher":
            # plain text has to be even number
            ciphert3 = ciphert3.upper()
            ciphert3 = ciphert3.replace(" ", "")

            # if message length is odd number, append 0 at the end
            len_chk = 0
            if len(ciphert3) % 2 != 0:
                ciphert3 += "0"
                len_chk = 1

            # ciphert3 to matrices
            row = 2
            col = int(len(ciphert3) / 2)
            ciphert32d = np.zeros((row, col), dtype=int)

            itr1 = 0
            itr2 = 0
            for i in range(len(ciphert3)):
                if i % 2 == 0:
                    ciphert32d[0][itr1] = int(ord(ciphert3[i]) - 65)
                    itr1 += 1
                else:
                    ciphert32d[1][itr2] = int(ord(ciphert3[i]) - 65)
                    itr2 += 1
            # for

            # key = input("Enter 4 letter Key String: ").upper()
            keyt3 = keyt3.replace(" ", "")

            # key to 2x2
            key2d = np.zeros((2, 2), dtype=int)
            itr3 = 0
            for i in range(2):
                for j in range(2):
                    key2d[i][j] = ord(keyt3[itr3]) - 65
                    itr3 += 1
            # for

            # finding determinant
            deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
            deter = deter % 26

            # finding multiplicative inverse
            mul_inv = -1
            for i in range(26):
                temp_inv = deter * i
                if temp_inv % 26 == 1:
                    mul_inv = i
                    break
                else:
                    continue
            # for

            # adjugate matrix
            # swapping
            key2d[0][0], key2d[1][1] = key2d[1][1], key2d[0][0]

            # changing signs
            key2d[0][1] *= -1
            key2d[1][0] *= -1

            key2d[0][1] = key2d[0][1] % 26
            key2d[1][0] = key2d[1][0] % 26

            # multiplying multiplicative inverse with adjugate matrix
            for i in range(2):
                for j in range(2):
                    key2d[i][j] *= mul_inv

            # modulo
            for i in range(2):
                for j in range(2):
                    key2d[i][j] = key2d[i][j] % 26

            # cipher to plain
            decryp_text = ""
            itr_count = int(len(ciphert3) / 2)
            if len_chk == 0:
                for i in range(itr_count):
                    temp1 = ciphert32d[0][i] * key2d[0][0] + ciphert32d[1][i] * key2d[0][1]
                    decryp_text += chr((temp1 % 26) + 65)
                    temp2 = ciphert32d[0][i] * key2d[1][0] + ciphert32d[1][i] * key2d[1][1]
                    decryp_text += chr((temp2 % 26) + 65)
                    # for
            else:
                for i in range(itr_count - 1):
                    temp1 = ciphert32d[0][i] * key2d[0][0] + ciphert32d[1][i] * key2d[0][1]
                    decryp_text += chr((temp1 % 26) + 65)
                    temp2 = ciphert32d[0][i] * key2d[1][0] + ciphert32d[1][i] * key2d[1][1]
                    decryp_text += chr((temp2 % 26) + 65)

            plaint6.insert(0, decryp_text.lower())

        elif clit3 == "Playfair":
            def create_matrix(key):
                key = key.upper()
                matrix = [[0 for i in range(5)] for j in range(5)]
                letters_added = []
                row = 0
                col = 0
                # add the key to the matrix
                for letter in key:
                    if letter not in letters_added:
                        matrix[row][col] = letter
                        letters_added.append(letter)
                    else:
                        continue
                    if (col == 4):
                        col = 0
                        row += 1
                    else:
                        col += 1
                # Add the rest of the alphabet to the matrix
                # A=65 ... Z=90
                for letter in range(65, 91):
                    if letter == 74:  # I/J are in the same position
                        continue
                    if chr(letter) not in letters_added:  # Do not add repeated letters
                        letters_added.append(chr(letter))

                # print (len(letters_added), letters_added)
                index = 0
                for i in range(5):
                    for j in range(5):
                        matrix[i][j] = letters_added[index]
                        index += 1
                return matrix

            # Adding fillers if the same letter is in a pair
            def separate_same_letters(message):
                index = 0
                while (index < len(message)):
                    l1 = message[index]
                    if index == len(message) - 1:
                        message = message + 'X'
                        index += 2
                        continue
                    l2 = message[index + 1]
                    if l1 == l2:
                        message = message[:index + 1] + "X" + message[index + 1:]
                    index += 2
                return message

            # Return the index of a letter in the matrix
            # This will be used to know what rule (1-4) to apply
            def indexOf(letter, matrix):
                for i in range(5):
                    try:
                        index = matrix[i].index(letter)
                        return (i, index)
                    except:
                        continue

            # Implementation of the playfair cipher
            # If encrypt=True the method will encrypt the message
            # otherwise the method will decrypt

            message = ciphert3
            key = keyt3
            inc = 1

            def playfair(key, message, encrypt=True):
                inc = 1
                if encrypt == False:
                    inc = -1
                matrix = create_matrix(key)
                message = message.upper()
                message = message.replace(' ', '')
                message = separate_same_letters(message)
                cipher_text = ''
                for (l1, l2) in zip(message[0::2], message[1::2]):
                    row1, col1 = indexOf(l1, matrix)
                    row2, col2 = indexOf(l2, matrix)
                    if row1 == row2:  # Rule 2, the letters are in the same row
                        cipher_text += matrix[row1][(col1 + inc) % 5] + matrix[row2][(col2 + inc) % 5]
                    elif col1 == col2:  # Rule 3, the letters are in the same column
                        cipher_text += matrix[(row1 + inc) % 5][col1] + matrix[(row2 + inc) % 5][col2]
                    else:  # Rule 4, the letters are in a different row and column
                        cipher_text += matrix[row1][col2] + matrix[row2][col1]

                plaint6.insert(0, cipher_text)

            print(playfair(keyt3, ciphert3, False))

        elif clit3 == "Columnar":

            plaintext4 = ""

            # track key indices
            k_indx = 0

            # track msg indices
            msg_indx = 0
            msg_len = float(len(ciphert3))
            msg_lst = list(ciphert3)

            # calculate column of the matrix
            col = len(keyt3)

            # calculate maximum row of the matrix
            row = int(math.ceil(msg_len / col))

            # convert key into list and sort
            # alphabetically so we can access
            # each character by its alphabetical position.
            key_lst = sorted(list(keyt3))

            # create an empty matrix to
            # store deciphered message
            dec_cipher = []
            for _ in range(row):
                dec_cipher += [[None] * col]

            # Arrange the matrix column wise according
            # to permutation order by adding into new matrix
            for _ in range(col):
                curr_idx = keyt3.index(key_lst[k_indx])

                for j in range(row):
                    dec_cipher[j][curr_idx] = msg_lst[msg_indx]
                    msg_indx += 1
                k_indx += 1

            # convert decrypted msg matrix into a string
            try:
                plaintext4 = ''.join(sum(dec_cipher, []))
            except TypeError:
                raise TypeError("This program cannot",
                                "handle repeating words.")

            null_count = plaintext4.count('_')

            if null_count > 0:
                return plaintext4[: -null_count]

            plaint6.insert(0, plaintext4)

        elif clit3 == "DES":
            # pt = "123456ABCD132536"
            # key = "AABB09182736CCDD"

            # Hexadecimal to binary conversion

            def hex2bin(s):
                mp = {'0': "0000",
                      '1': "0001",
                      '2': "0010",
                      '3': "0011",
                      '4': "0100",
                      '5': "0101",
                      '6': "0110",
                      '7': "0111",
                      '8': "1000",
                      '9': "1001",
                      'a': "1010",
                      'b': "1011",
                      'c': "1100",
                      'd': "1101",
                      'e': "1110",
                      'f': "1111"}
                bin = ""
                for i in range(len(s)):
                    bin = bin + mp[s[i]]
                return bin

            # Binary to  hexadecimal conversion

            def bin2hex(s):
                mp = {"0000": '0',
                      "0001": '1',
                      "0010": '2',
                      "0011": '3',
                      "0100": '4',
                      "0101": '5',
                      "0110": '6',
                      "0111": '7',
                      "1000": '8',
                      "1001": '9',
                      "1010": 'a',
                      "1011": 'b',
                      "1100": 'c',
                      "1101": 'd',
                      "1110": 'e',
                      "1111": 'f'}
                hex = ""
                for i in range(0, len(s), 4):
                    ch = ""
                    ch = ch + s[i]
                    ch = ch + s[i + 1]
                    ch = ch + s[i + 2]
                    ch = ch + s[i + 3]
                    hex = hex + mp[ch]

                return hex

            # Binary to decimal conversion

            def bin2dec(binary):

                binary1 = binary
                decimal, i, n = 0, 0, 0
                while (binary != 0):
                    dec = binary % 10
                    decimal = decimal + dec * pow(2, i)
                    binary = binary // 10
                    i += 1
                return decimal

            # Decimal to  binary conversion

            def dec2bin(num):
                res = bin(num).replace("0b", "")
                if (len(res) % 4 != 0):
                    div = len(res) / 4
                    div = int(div)
                    counter = (4 * (div + 1)) - len(res)
                    for i in range(0, counter):
                        res = '0' + res
                return res

            # Permute function to rearrange the bits

            def permute(k, arr, n):
                permutation = ""
                for i in range(0, n):
                    permutation = permutation + k[arr[i] - 1]
                return permutation

            # shifting the bits towards left by nth shifts

            def shift_left(k, nth_shifts):
                s = ""
                for i in range(nth_shifts):
                    for j in range(1, len(k)):
                        s = s + k[j]
                    s = s + k[0]
                    k = s
                    s = ""
                return k

            # calculating xow of two strings of binary number a and b

            def xor(a, b):
                ans = ""
                for i in range(len(a)):
                    if a[i] == b[i]:
                        ans = ans + "0"
                    else:
                        ans = ans + "1"
                return ans

            # Table of Position of 64 bits at initial level: Initial Permutation Table
            initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                            60, 52, 44, 36, 28, 20, 12, 4,
                            62, 54, 46, 38, 30, 22, 14, 6,
                            64, 56, 48, 40, 32, 24, 16, 8,
                            57, 49, 41, 33, 25, 17, 9, 1,
                            59, 51, 43, 35, 27, 19, 11, 3,
                            61, 53, 45, 37, 29, 21, 13, 5,
                            63, 55, 47, 39, 31, 23, 15, 7]

            # Expansion D-box Table
            exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
                     6, 7, 8, 9, 8, 9, 10, 11,
                     12, 13, 12, 13, 14, 15, 16, 17,
                     16, 17, 18, 19, 20, 21, 20, 21,
                     22, 23, 24, 25, 24, 25, 26, 27,
                     28, 29, 28, 29, 30, 31, 32, 1]

            # Straight Permutation Table
            per = [16, 7, 20, 21,
                   29, 12, 28, 17,
                   1, 15, 23, 26,
                   5, 18, 31, 10,
                   2, 8, 24, 14,
                   32, 27, 3, 9,
                   19, 13, 30, 6,
                   22, 11, 4, 25]

            # S-box Table
            sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

                    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

                    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

                    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

                    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

                    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

                    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

                    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

            # Final Permutation Table
            final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                          39, 7, 47, 15, 55, 23, 63, 31,
                          38, 6, 46, 14, 54, 22, 62, 30,
                          37, 5, 45, 13, 53, 21, 61, 29,
                          36, 4, 44, 12, 52, 20, 60, 28,
                          35, 3, 43, 11, 51, 19, 59, 27,
                          34, 2, 42, 10, 50, 18, 58, 26,
                          33, 1, 41, 9, 49, 17, 57, 25]

            def encrypt(plaintt1, rkb, rk):
                plaintt1 = hex2bin(plaintt1)

                # Initial Permutation
                plaintt1 = permute(plaintt1, initial_perm, 64)
                # print("After initial permutation", bin2hex(pt))

                # Splitting
                left = plaintt1[0:32]
                right = plaintt1[32:64]
                for i in range(0, 16):
                    # Expansion D-box: Expanding the 32 bits data into 48 bits
                    right_expanded = permute(right, exp_d, 48)

                    # XOR RoundKey[i] and right_expanded
                    xor_x = xor(right_expanded, rkb[i])

                    # S-boxex: substituting the value from s-box table by calculating row and column
                    sbox_str = ""
                    for j in range(0, 8):
                        row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                        col = bin2dec(
                            int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                        val = sbox[j][row][col]
                        sbox_str = sbox_str + dec2bin(val)

                    # Straight D-box: After substituting rearranging the bits
                    sbox_str = permute(sbox_str, per, 32)

                    # XOR left and sbox_str
                    result = xor(left, sbox_str)
                    left = result

                    # Swapper
                    if (i != 15):
                        left, right = right, left
                # print("Round ", i + 1, " ", bin2hex(left),
                # " ", bin2hex(right), " ", rk[i])

                # Combination
                combine = left + right

                # Final permutation: final rearranging of bits to get cipher text
                cipher_text = permute(combine, final_perm, 64)
                return cipher_text

            # Key generation
            # --hex to binary
            keyt3 = hex2bin(keyt3)

            # --parity bit drop table
            keyp = [57, 49, 41, 33, 25, 17, 9,
                    1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27,
                    19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12, 4]

            # getting 56 bit key from 64 bit using the parity bits
            keyt3 = permute(keyt3, keyp, 56)

            # Number of bit shifts
            shift_table = [1, 1, 2, 2,
                           2, 2, 2, 2,
                           1, 2, 2, 2,
                           2, 2, 2, 1]

            # Key- Compression Table : Compression of key from 56 bits to 48 bits
            key_comp = [14, 17, 11, 24, 1, 5,
                        3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8,
                        16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32]

            # Splitting
            left = keyt3[0:28]  # rkb for RoundKeys in binary
            right = keyt3[28:56]  # rk for RoundKeys in hexadecimal

            rkb = []
            rk = []
            for i in range(0, 16):
                # Shifting the bits by nth shifts by checking from shift table
                left = shift_left(left, shift_table[i])
                right = shift_left(right, shift_table[i])

                # Combination of left and right string
                combine_str = left + right

                # Compression of key from 56 to 48 bits
                round_key = permute(combine_str, key_comp, 48)

                rkb.append(round_key)
                rk.append(bin2hex(round_key))

            rkb_rev = rkb[::-1]
            rk_rev = rk[::-1]
            text = bin2hex(encrypt(ciphert3, rkb_rev, rk_rev))

            plaint6.insert(0, text)


senderwindow = senderwindow(root)
root.mainloop()

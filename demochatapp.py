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





DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
FONT = ("Helvetica", 17)
FONT1 = ("Helvetica",25)
WHITE= 'white'
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
    def __init__(self,master):
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

        clicked = StringVar()    #use clicked.get() to get selected item by user

        clicked.set(options[0])

        techniquetype = tk.OptionMenu(middle_frame, clicked, *options)  # command = select and write select function sepreately
        techniquetype.grid(row=4, column=1, pady=10)

        encryptbutton = (tk.Button(middle_frame, text="Encrypt", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE ,command= lambda: self.Encryption(ciphertextbox, plaintextbox,keybox,clicked) ))
        encryptbutton.grid(row=4, column=2, pady=10)    # style = "Tbutton"


        cipherlabel = tk.Label(middle_frame, text="Ciphertext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        cipherlabel.grid(row=5, column=0, sticky=tk.NSEW, pady=10)

        ciphertextbox = tk.Entry(middle_frame , font=FONT, bg=MEDIUM_GREY, fg='white', )
        ciphertextbox.grid(row=5, column=1, sticky=tk.NSEW, pady=10)


        sendbutton = (tk.Button(middle_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command=lambda: self.receiver(ciphertextbox) ))
        sendbutton.grid(row=5, column=2, padx=20, pady=10)

    def Encryption(self, ciphert6, plaintt, keyt, clit ):

        plaintt1 = plaintt.get()
        plaintt1 = plaintt1.lower()
        keyt1 = keyt.get()
        keyt1 = keyt1.lower()
        clit1 = clit.get()

        if clit1 == "Caesar cipher":
                shift = 3
                alphabet = string.ascii_lowercase
                shifted =  alphabet[shift:] + alphabet[:shift]
                table =str.maketrans(alphabet, shifted)

                encrypted1 = plaintt1.translate(table)
                ciphert6.insert(0,encrypted1)




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

            ciphert6.insert(0,cipher2)

        elif clit1 == "Polyalphabetic":
            alphabet = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
            # example key will be like "lemon"
            keyt1 = keyt1 * len(plaintt1)

            cypherText = ''

            count = 0

            for letter in plaintt1:
                if letter in string.ascii_lowercase:

                    shift = ord(keyt1[count])- ord('a')
                    cypherLetter = chr((ord(letter)-ord('a') + shift) % 26 + ord ('a'))
                    cypherText = cypherText + cypherLetter
                    count = ( count + 1) % len(keyt1)

                else:
                    cypherText = cypherText + letter

            ciphert6.insert(0,cypherText)

        elif clit1 == "Hill cipher":
            # plain text has to be even number otherwise just write x at the end
            #Because it works on 2x1 matrix

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

            ciphert6.insert(0,encryp_text)

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

             ciphert6.insert(0,cipher8)    



    def receiver(self, ciphertextbook):
        root1 = Toplevel(root)
        root1.geometry("500x250")
        root1.title("Secure chat App")
        root1.resizable(False, False)

        ciphertext= ciphertextbook.get()
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
        ciphertextbox1 = tk.Entry(middle_frame1, width = 20,font=FONT, bg=MEDIUM_GREY, fg='white', borderwidth=1, relief="groove",)
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


        techniquetype1 = tk.OptionMenu(middle_frame1, clicked, *options) #command = select and write select function sepreately
        techniquetype1.grid(row=4, column=1, pady=8)

        techniquebutton1 = (tk.Button(middle_frame1, text="Decrypt", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command= lambda: self.Decryption(plaintextbox1 ,ciphertextbox1,keybox1,clicked) ))
        techniquebutton1.grid(row=4, column=2, pady=10)

        plainlabel1 = tk.Label(middle_frame1, text="Plaintext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        plainlabel1.grid(row=5, column=0, sticky=tk.NSEW, pady=10)

        plaintextbox1 = tk.Entry(middle_frame1, font=FONT, bg=MEDIUM_GREY, fg='white', )
        plaintextbox1.grid(row=5, column=1, sticky=tk.NSEW, pady=10)


    def Decryption(self,plaint6, ciphert2, keyt2, clit2 ):
        ciphert3 = ciphert2.get() #  "elq pezaz tbi" #
        # ciphert3 = ciphert2.lower()
        keyt3 = keyt2.get()
        keyt3 = keyt3.lower()
        clit3 = clit2.get()

        if clit3== "Caesar cipher":
            output_text = ""
            plaintt3 = ciphert3.lower()
            # for c in plaintt3:
            # 
            #     if c in string.ascii_letters:
            #         temp = ord('c') + keyt3
            # 
            #         if temp > ord('z'):
            #             temp = temp - 1
            # 
            #         output_text = output_text + chr(temp)
            #     else:
            #         output_text = output_text + c
            # print(output_text)
            shift_number = 3
            alphabets = string.ascii_lowercase + string.ascii_lowercase
            for i in range(len(ciphert3)):
                if ciphert3[i] == ' ':
                    ciphert3[i] = ' '
                else:
                    new_letter = alphabets.index(ciphert3[i]) - shift_number
                    ciphert3[i] = alphabets[new_letter]
                # convert the list back to a string
            a=print(''.join(map(str, ciphert3)))
            plaint6.insert(0,a)

        elif clit3 == "Monoalphabetic":
            #key3t = "zebraistpdcfghjklmnoquywxy"
            plaintext3 = ""
            for c in ciphert3:
                if c in string.ascii_lowercase:
                    index = keyt3.find(c)
                    plaintext3 += chr(index + ord('a'))
                else:
                    plaintext3 = plaintext3 + c
            plaint6.insert(0,plaintext3)

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

                    ciphert4= ciphert4 + cypherText1
                    count= (count + 1) % len(keyt3)

                else:
                    ciphert4 = ciphert4 + c

            plaint6.insert(0,ciphert4)
            
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



            plaint6.insert(0,decryp_text.lower())
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
  
          
            plaint6.insert(0,plaintext4)    

senderwindow= senderwindow(root)
root.mainloop()

  

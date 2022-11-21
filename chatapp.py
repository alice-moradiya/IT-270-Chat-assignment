import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import *
import tkinter.ttk as ttk
import sys
import time





DARK_GREY = '#121212'
MEDIUM_GREY = '#1F1B24'
OCEAN_BLUE = '#464EB8'
FONT = ("Helvetica", 17)
FONT1 = ("Helvetica",25)
WHITE= 'white'
SMALL_FONT = ("Helvetica", 13)
BUTTON_FONT = ("Helvetica", 13)

root = tk.Tk()
root.geometry("500x250")
root.title("Secure chat App")
root.resizable(False, False)

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

        clicked = StringVar()
        clicked.set(options[0])

        techniquetype = tk.OptionMenu(middle_frame, root, clicked,
                                      *options)  # command = select and write select function sepreately
        techniquetype.grid(row=4, column=1, pady=10)

        techniquebutton = (
            tk.Button(middle_frame, text="Encypt", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, ))
        techniquebutton.grid(row=4, column=2, pady=10)

        cipherlabel = tk.Label(middle_frame, text="Ciphertext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        cipherlabel.grid(row=5, column=0, sticky=tk.NSEW, pady=10)

        ciphertextbox = tk.Entry(middle_frame, font=FONT, bg=MEDIUM_GREY, fg='white', )
        ciphertextbox.grid(row=5, column=1, sticky=tk.NSEW, pady=10)

        sendbutton = (tk.Button(middle_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, command= self.open ))
        sendbutton.grid(row=5, column=2, padx=20, pady=10)

    def open(self):
        Recieverwindow= recieverwindow()


root1 = tk.Tk()
root1.geometry("500x250")
root1.title("Secure chat App")
root1.resizable(False, False)

class recieverwindow:
    def __init__(self):
        top_frame1 = tk.Frame(root1, width=500, height=80, bg=DARK_GREY)
        top_frame1.grid(row=0, column=0, sticky=tk.NSEW)  # north,south, east,west

        middle_frame1 = tk.Frame(root1, width=500, height=550, bg=MEDIUM_GREY)
        middle_frame1.grid(row=1, column=0, sticky=tk.NSEW)

        username_lable1 = tk.Label(top_frame1, text="Reciever", font=FONT1, bg=DARK_GREY, fg='white')
        username_lable1.grid(sticky=tk.NSEW, padx=200)

        plaintext1 = tk.Label(middle_frame1, text="Ciphertext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor='w')
        plaintext1.grid(row=2, column=0, sticky=tk.NSEW, pady=10)

        plaintextbox1 = tk.Entry(middle_frame1, font=FONT, bg=MEDIUM_GREY, fg='white', )
        plaintextbox1.grid(row=2, column=1, sticky=tk.NSEW, pady=10)

        key_lable1 = tk.Label(middle_frame1, text="Key:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        key_lable1.grid(row=3, column=0, sticky=tk.NSEW, pady=10)

        keybox1 = tk.Entry(middle_frame1, font=FONT, bg=MEDIUM_GREY, fg='white', )
        keybox1.grid(row=3, column=1, sticky=tk.NSEW, pady=10)

        technique_label1 = tk.Label(middle_frame1, text="Technique:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        technique_label1.grid(row=4, column=0, sticky=tk.NSEW, pady=10)

        options1 = ["Caesar cipher", "Monoalphabetic", "Polyalphabetic", "Hill cipher"
            , "Playfair", "OTP", "Rail fence", "Columnar"
            , "DES", "AES", "RC4", "RSA", "ECC"
            , "DH for key exchange", "Hashing (SHA) for integrity checking", "DSA for signature"]

        clicked1 = StringVar()
        clicked1.set(options1[0])

        techniquetype = tk.OptionMenu(middle_frame1, root1, clicked1,
                                      *options1)  # command = select and write select function sepreately
        techniquetype.grid(row=4, column=1, pady=10)

        techniquebutton1 = (
            tk.Button(middle_frame1, text="Decypt", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE, ))
        techniquebutton1.grid(row=4, column=2, pady=10)

        cipherlabel1 = tk.Label(middle_frame1, text="Plaintext:", font=FONT, bg=MEDIUM_GREY, fg='white', anchor="w")
        cipherlabel1.grid(row=5, column=0, sticky=tk.NSEW, pady=10)

        ciphertextbox1 = tk.Entry(middle_frame1, font=FONT, bg=MEDIUM_GREY, fg='white', )
        ciphertextbox1.grid(row=5, column=1, sticky=tk.NSEW, pady=10)



senderwindow= senderwindow(root)
root.mainloop()
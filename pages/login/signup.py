import customtkinter
from tkinter import messagebox
from tkinter import *
import bcrypt
from db_creation import db, user
from flask import Flask
import login

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

def switch_to_login():
    login.login_page()

def signup_page():
    root = customtkinter.CTk()
    root.title("Sign Up")
    root.geometry("500x500")
    
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

    def signup(username_entry, password_entry, account_type_var):
        username = username_entry.get()
        password = password_entry.get()
        account_type = account_type_var.get()
        existing_user = user.query.filter_by(username=username).first()
        if existing_user:
            messagebox.showerror("Sign Up Failed", "Username already exists.")
        else:
            # Hash the password
            hashed_password = hash_password(password)
            # Create a new user
            new_user = user(username=username, password=hashed_password, account_type=account_type)
            db.session.add(new_user)
            db.session.commit()
            # Clear entry fields
            username_entry.delete(0, 'end')
            password_entry.delete(0, 'end')
            messagebox.showinfo("Sign Up Successful", "Your account has been created successfully!")

    def switch_to_login():
        login.login_page()

    frame = customtkinter.CTkFrame(master = root)
    frame.pack(pady = 20, padx = 60, expand = True)

    signup_label = customtkinter.CTkLabel(master = frame, text = "Sign up")
    signup_label.pack(pady = 12, padx = 10)

    username_entry = customtkinter.CTkEntry(master = frame, placeholder_text = "Username")
    username_entry.pack(pady = 12, padx = 10)

    password_entry = customtkinter.CTkEntry(master = frame, placeholder_text = "Password")
    password_entry.pack(pady = 12, padx = 10)

    button = customtkinter.CTkButton(master = frame, text = "Sign up", command = lambda: signup(username_entry, password_entry, account_type_var))
    button.pack(pady = 12, padx = 10)

    account_type_label = customtkinter.CTkLabel(root, text="Account Type:")
    account_type_label.pack()
    account_type_var = customtkinter.StringVar(root)
    account_type_var.set("standard")  # Default value
    account_type_dropdown = customtkinter.CTkOptionMenu(root, variable = account_type_var, values=["admin", "standard"])
    account_type_dropdown.pack(pady = 4)

    login_label = customtkinter.CTkLabel(master = frame, text = "Already have an account?")
    login_label.pack(pady = 12, padx = 10)

    login_button = customtkinter.CTkButton(master = frame, text = "Login", cursor = 'hand2', command = switch_to_login)
    login_button.pack(pady = 1, padx = 10)

    root.mainloop()

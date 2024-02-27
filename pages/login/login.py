import customtkinter
from tkinter import messagebox
from tkinter import *
import bcrypt
from db_creation import user

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

def login_page():
    root = customtkinter.CTk()
    root.geometry("500x350")

    def login():
        username = username_entry.get()
        password = password_entry.get()
        user_data = user.query.filter_by(username=username).first()
        if user_data:
            stored_password = user_data.password
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                messagebox.showinfo("Login Successful", "Welcome back, " + username + "!")
            else:
                messagebox.showerror("Login Failed", "Incorrect password.")
        else:
            messagebox.showerror("Login Failed", "Username not found.")
        

    frame = customtkinter.CTkFrame(master = root)
    frame.pack(pady = 20, padx = 60, expand = True)

    label = customtkinter.CTkLabel(master = frame, text = "Login System")
    label.pack(pady = 12, padx = 10)

    username_entry = customtkinter.CTkEntry(master = frame, placeholder_text = "Username")
    username_entry.pack(pady = 12, padx = 10)

    password_entry = customtkinter.CTkEntry(master = frame, placeholder_text = "Password")
    password_entry.pack(pady = 12, padx = 10)

    button = customtkinter.CTkButton(master = frame, text = "Login", command = login)
    button.pack(pady = 12, padx = 10)

    checkbox = customtkinter.CTkCheckBox(master = frame, text = "Remember me")
    checkbox.pack(pady = 12, padx = 10)

    print("Login Seccessfully done")

    root.mainloop()
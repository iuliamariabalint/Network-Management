import customtkinter
from tkinter import messagebox
from tkinter import *
import bcrypt
import signup
from db_creation import db, user
from flask import Flask
import router_data

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/balin/Desktop/SQLite_DB/net-management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

def switch_to_signup():
    signup.signup_page()

def switch_to_main():
    router_data.main_page()

def login_page():
    root = customtkinter.CTk()
    
    # Get the screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Set the window size to the screen resolution
    root.geometry(f"{screen_width}x{screen_height}")
    # root.geometry("1000x1000")

    def login():
        username = username_entry.get()
        password = password_entry.get()
        user_data = user.query.filter_by(username=username).first()
        if user_data:
            stored_password = user_data.password
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                switch_to_main()
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

    signup_button = customtkinter.CTkButton(master = frame, text = "Sign up", cursor = 'hand2', command = switch_to_signup)
    signup_button.pack(pady = 1, padx = 10)

    print("Login Seccessfully done")

    root.mainloop()

if __name__ == '__main__':
    with app.app_context():
        login_page()
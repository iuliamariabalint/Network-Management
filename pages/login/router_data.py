import customtkinter
from tkinter import *
import bcrypt
import json
import main

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")
root = customtkinter.CTk()
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

root.geometry(f"{screen_width}x{screen_height}")

def switch_to_main():
    main.main_page()

def router_data_page():
    
    def hash_password(password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')

    def save_router_data():
        # Hash the password
        #hashed_password = hash_password(password_entry.get())
        data = {
            "router_user": user_entry.get(),
            "router_password": password_entry.get(),
            "ip_address": "192.168.99.1"

        }
        with open("router_data.json", "w") as file:
            json.dump(data, file)
        
        switch_to_main()

        

    frame = customtkinter.CTkFrame(master = root)
    frame.pack(pady = 20, padx = 60, expand = True)

    info = customtkinter.CTkLabel(master = frame, text = "Please enter the router data")
    info.pack(pady = 12, padx = 10)

    user_entry = customtkinter.CTkEntry(master = frame, placeholder_text = "router admin user")
    user_entry.pack(pady = 12, padx = 10)

    password_entry = customtkinter.CTkEntry(master = frame, placeholder_text = "router password", show="*")
    password_entry.pack(pady = 12, padx = 10)

    button = customtkinter.CTkButton(master = frame, text = "Save", command = save_router_data)
    button.pack(pady = 12, padx = 10)

    root.mainloop()

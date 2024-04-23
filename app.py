import tkinter as tk
from tkinter import *
from tkinter import messagebox
import customtkinter as ctk
from flask import Flask
from db_creation import db, user
import bcrypt
import atexit, os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/balin/Desktop/SQLite_DB/net-management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("green")

# class BaseFrame(ctk.CTkFrame):
#     def __init__(self, master, *args, **kwargs):
#         super().__init__(master, *args, **kwargs)
#         self.create_widgets()

#     def create_widgets(self):
#         pass

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

       ## Setting up Initial Things
        self.title("net-management")
        self.geometry("720x550")
        self.resizable(True, True)
        #self.iconphoto(False, tk.PhotoImage(file="assets/title_icon.png"))
    
        ## Creating a container
        container = ctk.CTkFrame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        ## Initialize Frames
        self.frames = {}
        self.LoginPage = LoginPage
        self.SignupPage = SignupPage
        self.RouterDataPage = RouterDataPage
        self.HomePage = HomePage
        self.ManagedDevices = ManagedDevices

        ## Defining Frames and Packing it
        for F in {LoginPage, SignupPage, RouterDataPage, HomePage, ManagedDevices}:
            frame = F(self, container)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky = "nsew")    
           
        self.show_frame(LoginPage)
        atexit.register(self.delete_json_file)
    def show_frame(self, cont):
        frame = self.frames[cont]
        menubar = frame.create_menubar(self)
        self.configure(menu=menubar)
        frame.tkraise()                         ## This line will put the frame on front
    
    def delete_json_file(self):
        file_path = "router_data.json"  # Specify the path to your JSON file
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"The file '{file_path}' has been deleted.")
        else:
            print(f"The file '{file_path}' does not exist.")
#---------------------------------------- LOGINPAGE / CONTAINER ------------------------------------------------------------------------
        
class LoginPage(ctk.CTkFrame):
    def __init__(self, parent, container):
    
        super().__init__(container)

        label = ctk.CTkLabel(self, text="Login Page")
        label.pack(pady=0,padx=0)
        username_entry = ctk.CTkEntry(self, placeholder_text = "Username")
        username_entry.pack(pady = 12, padx = 10)

        password_entry = ctk.CTkEntry(self, placeholder_text = "Password", show = "*")
        password_entry.pack(pady = 12, padx = 10)

        button = ctk.CTkButton(self, text = "Login", command = lambda: login(username_entry, password_entry))
        button.pack(pady = 12, padx = 10)

        checkbox = ctk.CTkCheckBox(self, text = "Remember me")
        checkbox.pack(pady = 12, padx = 10)

        signup_button = ctk.CTkButton(self, text = "Sign up", cursor = 'hand2', command = lambda: parent.show_frame(parent.SignupPage))
        signup_button.pack(pady = 1, padx = 10)

        def login(username, password):
            username = username_entry.get()
            password = password_entry.get()
            user_data = user.query.filter_by(username=username).first()
            if user_data:
                stored_password = user_data.password
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    parent.show_frame(parent.RouterDataPage)
                else:
                    messagebox.showerror("Login Failed", "Incorrect password.")
            else:
                messagebox.showerror("Login Failed", "Username not found.")

    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)
        return menubar
        
#---------------------------------------- SIGNUP-PAGE / CONTAINER ------------------------------------------------------------------------

class SignupPage(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)

        label = ctk.CTkLabel(self, text="Signup Page")
        label.pack(pady=0,padx=0)

        username_entry = ctk.CTkEntry(self, placeholder_text = "Username")
        username_entry.pack(pady = 12, padx = 10)

        password_entry = ctk.CTkEntry(self, placeholder_text = "Password", show="*")
        password_entry.pack(pady = 12, padx = 10)

        button = ctk.CTkButton(self, text = "Sign up", command = lambda: signup(username_entry, password_entry, account_type_var))
        button.pack(pady = 12, padx = 10)

        account_type_label = ctk.CTkLabel(self, text="Account Type:")
        account_type_label.pack()
        account_type_var = ctk.StringVar(self)
        account_type_var.set("standard")  # Default value
        account_type_dropdown = ctk.CTkOptionMenu(self, variable = account_type_var, values=["admin", "standard"])
        account_type_dropdown.pack(pady = 4)

        login_label = ctk.CTkLabel(self, text = "Already have an account?")
        login_label.pack(pady = 12, padx = 10)

        login_button = ctk.CTkButton(self, text = "Login", cursor = 'hand2', command = lambda: parent.show_frame(parent.LoginPage))
        login_button.pack(pady = 1, padx = 10)

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

        def hash_password(password):
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed_password.decode('utf-8')
    
    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)
        return menubar

#---------------------------------------- ROUTER-DATA-PAGE / CONTAINER ------------------------------------------------------------------------
import json
class RouterDataPage(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)

        info = ctk.CTkLabel(self, text = "Please enter the router data")
        info.pack(pady = 12, padx = 10)

        user_entry = ctk.CTkEntry(self, placeholder_text = "router admin user")
        user_entry.pack(pady = 12, padx = 10)

        password_entry = ctk.CTkEntry(self, placeholder_text = "router password", show="*")
        password_entry.pack(pady = 12, padx = 10)

        button = ctk.CTkButton(self, text = "Save", command = lambda: save_router_data(user_entry, password_entry))
        button.pack(pady = 12, padx = 10)

        def save_router_data(user, password):
        # Hash the password
        #hashed_password = hash_password(password_entry.get())
            user = user_entry
            password = password_entry
            data = {
            "router_user": user.get(),
            "router_password": password.get(),
            "ip_address": "192.168.99.1"
            }
            try:
                host = data['ip_address']
                username = data['router_user']
                password = data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password, timeout=5) 
                with open("router_data.json", "w") as file:
                    json.dump(data, file)
                parent.show_frame(parent.HomePage)
                return True 
            except paramiko.AuthenticationException:
                messagebox.showerror("Error","Wrong credentials")
                return False
            except Exception as e:
                messagebox.showerror("Error", f"Failed to connect to the router: {str(e)}")
            finally:
                client.close()
            
    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)
        return menubar

#---------------------------------------- HOME PAGE FRAME / CONTAINER ------------------------------------------------------------------------
import paramiko

class HomePage(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)
        self.create_widgets()

    def create_widgets(self):
            try:
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)

                command = "cat /tmp/dhcp.leases"

                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)

                stdin, stdout, stderr = client.exec_command(command)
                active_clients = stdout.read().decode()
                client.close()
                dhcp_leases = []
                for line in active_clients.split('\n'):
                    if line.strip():
                        timestamp, mac_address, ip_address, hostname, client_id = line.split()
                        dhcp_lease = {
                            "timestamp": timestamp,
                            "mac_address": mac_address,
                            "ip_address": ip_address,
                            "hostname": hostname,
                            "client_id": client_id
                        }
                        dhcp_leases.append(dhcp_lease)

                with open("active_clients.json", "w") as file:
                    json.dump(dhcp_leases, file, indent = 4)

                self.columnconfigure(0, weight=1)
                self.columnconfigure(1, weight=1)

                label = ctk.CTkLabel(self, text="Home Page")
                label.grid(row = 0, column = 0, sticky = E, pady = 20, padx = 10)

                for i, lease in enumerate(dhcp_leases):
                    client_info = f"MAC Address: {lease['mac_address']}\nIP Address: {lease['ip_address']}\nHostname: {lease['hostname']}\nClient ID: {lease['client_id']}"
                    label = ctk.CTkLabel(self, text=client_info)
                    label.grid(row=i+1, column=0, sticky = E, pady=30, padx=10)
                    button = ctk.CTkButton(self, text="Manage device")
                    button.grid(row=i+1, column=1, sticky = W, pady=45, padx=10)
                    # with open("active_clients.json", "w") as file:
                    #     json.dump(dhcp_leases, file, indent = 4) 
                #print('lol')
            except FileNotFoundError:
                print("Fișierul JSON nu a fost găsit.")
            
            self.after(1000, self.create_widgets)

    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        ## Filemenu
        filemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=filemenu)
        filemenu.add_command(label="Managed devices", command=lambda: parent.show_frame(parent.ManagedDevices))
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=parent.quit)  

        ## help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()

        return menubar

import paramiko

class ManagedDevices(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)
        label = ctk.CTkLabel(self, text="Managed Devices")
        label.grid(row = 0, column = 0, sticky = E, pady = 20, padx = 10)


    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        ## Filemenu
        filemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=filemenu)
        filemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=parent.quit)  

        ## help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()

        return menubar


if __name__ == "__main__":
    with app.app_context():
        App().mainloop()
        
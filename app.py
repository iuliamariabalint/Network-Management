import tkinter as tk
from tkinter import *
from tkinter import messagebox
import customtkinter as ctk
from flask import Flask
from db_creation import db, user, settings
import bcrypt
import atexit, os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/balin/Desktop/SQLite_DB/net-management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("green")


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
        self.DeviceSettings = DeviceSettings
        self.Settings = Settings

        ## Defining Frames and Packing it
        for F in {LoginPage, SignupPage, RouterDataPage, HomePage, ManagedDevices, Settings, DeviceSettings}:
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
        pass
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
        pass

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
        pass

#---------------------------------------- HOME PAGE FRAME / CONTAINER ------------------------------------------------------------------------
import paramiko
from db_creation import device

class HomePage(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)

        self.parent_window = parent
        self.active_clients(parent)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        label = ctk.CTkLabel(self, text="Home Page")
        label.grid(row = 0, column = 0, sticky = E, pady = 20, padx = 10)

    def active_clients(self, parent):
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
            processed_macs = set()
            

            for i, line in enumerate(active_clients.split('\n')):
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

                try: 
                    if mac_address in processed_macs:
                        continue
                except:
                    return None

                processed_macs.add(mac_address)

                client_info = f"MAC Address: {mac_address}\nIP Address: {ip_address}\nHostname: {hostname}\nClient ID: {client_id}"
                label = ctk.CTkLabel(self, text=client_info)
                label.grid(row=i+1, column=0, sticky = E, pady=30, padx=10)

                existing_device = device.query.filter_by(MAC_address = mac_address).first()
                if existing_device:
                    manage_label = ctk.CTkLabel(self, text = "managed", text_color = "#5AD194", width=140)
                    manage_label.grid(row=i+1, column=1, sticky=W, pady=45, padx=10)
                else:
                    button = ctk.CTkButton(self, text="manage", command = lambda info = dhcp_lease: self.settings_modal(info))
                    button.grid(row=i+1, column=1, sticky = W, pady=45, padx=10)

        except FileNotFoundError:
            print("Fișierul JSON nu a fost găsit.")
        self.after(5000, self.active_clients, parent)

    def settings_modal(self, client_info):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Device data")
        #modal.geometry("300x200")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 - 150  # Center the modal horizontally
        modal_y = parent_y + parent_height // 2 - 100  # Center the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        hostname = client_info['hostname']
        mac_addr = client_info['mac_address']

        devicename_entry = ctk.CTkEntry(modal, width = max(len(hostname) * 7, 100))
        devicename_entry.insert(0, hostname)
        devicename_entry.pack(pady=10)

        mac_label = ctk.CTkLabel(modal, text = f"MAC Address: {mac_addr}")
        mac_label.pack(pady = 5)

        device_types = ['Router', 'Extender', 'Mobile', 'Laptop', 'Computer', 'TV', 'Other']
        device_type_dropdown = ctk.CTkOptionMenu(modal, values = device_types)
        device_type_dropdown.set("Select Device Type")
        device_type_dropdown.pack(pady = 5)

        def add_device(devicename, mac_addr, devicetype):
            device_name = devicename.get()
            device_type = devicetype.get()
            if device_type in device_types:
                # Add device in database
                device_ = device(device_name = device_name, MAC_address = mac_addr, device_type = device_type)
                db.session.add(device_)
                db.session.commit()
                modal.destroy()
            else: 
                messagebox.showerror("Error", "Please select a device type.")


        add_button = ctk.CTkButton(modal, text="Add", command = lambda: add_device(devicename_entry, mac_addr, device_type_dropdown))
        add_button.pack(side="top", anchor="n", padx=5, pady=5)


    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        filemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=filemenu)
        filemenu.add_command(label="Managed devices", command=lambda: parent.show_frame(parent.ManagedDevices))
        filemenu.add_command(label="Settings", command=lambda: parent.show_frame(parent.Settings)) 

        ## help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit) 

        return menubar

#-----------------------------------------------------MANAGED DEVICES FRAME / CONTAINER --------------------------------------------------

class ManagedDevices(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)
        self.parent_window = parent
        self.get_and_show_devices(parent)
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    def get_and_show_devices(self, parent):
        
        for widget in self.grid_slaves():
            widget.grid_remove()
        
        label = ctk.CTkLabel(self, text="Managed Devices")
        label.grid(row = 0, sticky = E, pady = 20, padx = 10)

        devices = db.session.query(device.device_name, device.MAC_address, device.device_type).all()
        for i, dev in enumerate(devices):
            device_data = f"{dev.device_name}\nMAC address: {dev.MAC_address}\nDevice type: {dev.device_type}"

            label = ctk.CTkLabel(self, text=device_data)
            label.grid(row=i+1, column=0, sticky=E, pady=45, padx=10)

            edit_button = ctk.CTkButton(self, text="edit", command= lambda dev = dev : self.edit_device(dev))
            edit_button.grid(row=i+1, column=1, sticky = NW, pady=55, padx=10)


        self.after(3000, self.get_and_show_devices, parent)

    def edit_device(self, dev):
        parent_container = self.master
        edit_frame = DeviceSettings(self.parent_window, parent_container,  device_info = dev)
        edit_frame.grid(row=0, column=0, sticky = "nsew")


    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        filemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=filemenu)
        filemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))
        filemenu.add_command(label="Settings", command=lambda: parent.show_frame(parent.Settings))
 
        ## help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit) 

        return menubar

#---------------------------------------------------DEVICE SETTINGS FRAME / CONTAINER --------------------------------------------------
class DeviceSettings(ctk.CTkFrame):
    def __init__(self, parent, container, device_info = ("", "", ""), *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        back_button = ctk.CTkButton(self, text = "\u2190", command=lambda: parent.show_frame(ManagedDevices), text_color = "white", fg_color = "transparent", hover_color = "#544D4D")
        back_button.pack(side="top", anchor="ne", padx=10, pady=10)
        title = ctk.CTkLabel(self, text="Device Settings")
        title.pack(pady = 5, padx = 10)

        self.parent = parent
        self.device_info = device_info
        self.show_device_settings()

    def show_device_settings(self):
        # Extract the device name, MAC address, and device type from the device_info tuple
        device_name, mac_address, device_type = self.device_info

        # Create an entry for the device name
        devicename_entry = ctk.CTkEntry(self, width = max(len(device_name) * 7, 100))
        devicename_entry.insert(0, device_name)
        devicename_entry.pack(pady=10)

        # Create a label for the MAC address
        mac_label = ctk.CTkLabel(self, text=f"MAC Address: {mac_address}")
        mac_label.pack(pady=5)

        # Create a dropdown menu for selecting device type
        device_type_var = ctk.StringVar(self)
        device_type_var.set(device_type)
        device_types = ['Router', 'Extender', 'Mobile', 'Laptop', 'Computer', 'TV', 'Other']
        device_type_dropdown = ctk.CTkOptionMenu(self, variable=device_type_var, values=device_types)
        device_type_dropdown.pack(pady=5)

        delete_button = ctk.CTkButton(self, fg_color="transparent", hover_color="#F24A3B", text="delete", command = lambda: delete(mac_address, self.parent))
        delete_button.pack(pady = 5)

        done_button = ctk.CTkButton(self, text="done", command = lambda: edit_device(self.parent, devicename_entry, mac_address, device_type_dropdown))
        done_button.pack(side="top", anchor="n", padx=5, pady=5)

        def delete(mac_addr, parent):
            existing_device = device.query.filter_by(MAC_address = mac_addr).first()
            if existing_device:
                db.session.delete(existing_device)
                db.session.commit()
                parent.show_frame(ManagedDevices)
    
        def edit_device(parent, devicename, mac_addr, devicetype):
            device_name = devicename.get()
            device_type = devicetype.get()
            existing_device = device.query.filter_by(MAC_address = mac_addr).first()
            if existing_device:
                db.session.delete(existing_device)
                db.session.commit()
            # Add device in database
            edited_device = device(device_name = device_name, MAC_address = mac_addr, device_type = device_type)
            db.session.add(edited_device)
            db.session.commit()
            parent.show_frame(ManagedDevices)

#---------------------------------------------------SETTINGS FRAME / CONTAINER --------------------------------------------------
from functools import partial
from db_creation import settings
from tkinter import ttk

class Settings(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)
        self.parent_window = parent

        self.get_and_show_settings(parent)
        
        self.columnconfigure(0, weight=1)

        label = ctk.CTkLabel(self, text="Settings")
        label.grid(row = 0, column = 0, sticky = N, pady = 20, padx = 10)

    def get_and_show_settings(self, parent):
        settings_list = db.session.query(settings.setting_name, settings.description).all()

        for i, setting in enumerate(settings_list):

            description = f"{setting.description}"
            name = f"{setting.setting_name}"
            button_command = partial(self.open_modal, parent, setting.setting_name)
            button = ctk.CTkButton(self, text = name, command = button_command)
            button.grid(row=i+1, column=0, sticky = N, pady=15, padx=10)
            label = ctk.CTkLabel(self, text=description)
            label.grid(row=i+1, column=0, sticky=N, pady=45, padx=10)

    def open_modal(self, parent, setting_name):
        modal_functions = {
            "Block Network Access": self.block_access_modal,
            "Network Usage Scheduler": self.time_restriction_modal,
        }

        modal_function = modal_functions.get(setting_name)

        if modal_function:
            modal_function()
        else:
            print("Modal function not found for setting:", setting_name)

    def block_access_modal(self):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Setting")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 - 150  # Center the modal horizontally
        modal_y = parent_y + parent_height // 2 - 100  # Center the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        title = ctk.CTkLabel(modal, text = "Block access")
        title.grid(pady = 5)

        action = "deny"
        action_label = ctk.CTkLabel(modal, text = f"Action: {action}")
        action_label.grid(pady=10)

        devices = db.session.query(device.device_name, device.MAC_address).all()
        device_info = {name: mac for name, mac in devices}

        def on_device_selected(event):
                    global selected_mac_address, src_mac
                    selected_device = device_dropdown.get()
                    selected_mac_address = device_info.get(selected_device)
                    
                    if selected_mac_address:
                        mac_label.configure(text=f"MAC Address: {selected_mac_address}")
                        src_mac = selected_mac_address
                        print("stored mac = ", src_mac)
                    else:
                        print("MAC address not found for device:", selected_device)
        
        device_dropdown = ttk.Combobox(modal, values=list(device_info.keys()), width = 30, state = "readonly")
        device_dropdown.set("Select Device")
        device_dropdown.grid(padx=10, pady=10)

        mac_label = ctk.CTkLabel(modal, text="MAC Address: ")
        mac_label.grid(padx=10, pady=10)

        device_dropdown.bind("<<ComboboxSelected>>", on_device_selected)

    def time_restriction_modal(self):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Setting")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 - 150  # Center the modal horizontally
        modal_y = parent_y + parent_height // 2 - 100  # Center the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        title = ctk.CTkLabel(modal, text = "Time Restriction Setting")
        title.grid(pady = 5)

        label = ctk.CTkLabel(modal, text = "Rule Name:")
        label.grid(pady = 10)

        setting_name = "Filter-Parental-Controls"
        settingname_entry = ctk.CTkEntry(modal, width = max(len(setting_name) * 7, 100))
        settingname_entry.insert(0, setting_name)
        settingname_entry.grid(pady=0)

        src = "lan"
        source = ctk.CTkLabel(modal, text = f"Source zone: {src}")
        source.grid(pady=10)

        devices = db.session.query(device.device_name, device.MAC_address).all()
        device_info = {name: mac for name, mac in devices}

        selected_mac_address = None
        src_mac = None

        def on_device_selected(event):
            global selected_mac_address, src_mac
            selected_device = device_dropdown.get()
            selected_mac_address = device_info.get(selected_device)
            
            if selected_mac_address:
                mac_label.configure(text=f"MAC Address: {selected_mac_address}")
                src_mac = selected_mac_address
                print("stored mac = ", src_mac)
            else:
                print("MAC address not found for device:", selected_device)
        
        device_dropdown = ttk.Combobox(modal, values=list(device_info.keys()), width = 30, state = "readonly")
        device_dropdown.set("Select Device")
        device_dropdown.grid(padx=10, pady=10)

        mac_label = ctk.CTkLabel(modal, text="MAC Address: ")
        mac_label.grid(padx=10, pady=10)

        device_dropdown.bind("<<ComboboxSelected>>", on_device_selected)

        dest = "wan"
        destination = ctk.CTkLabel(modal, text = f"Destination zone: {dest}")
        destination.grid(pady=10)

        start_time = ctk.CTkEntry(modal, placeholder_text = "Start Time (hh:mm:ss)")
        start_time.grid(pady = 12)

        stop_time = ctk.CTkEntry(modal, placeholder_text = "Stop Time (hh:mm:ss)")
        stop_time.grid(pady = 12)

        weekdays_list = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        weekdays_dropdown = ctk.CTkOptionMenu(modal, values = weekdays_list)
        weekdays_dropdown.set("Select restriction weekdays")
        weekdays_dropdown.grid(pady=10)

        target = "REJECT"
        action = ctk.CTkLabel(modal, text = f"Action: {target}")
        action.grid(pady=10)

        done_button = ctk.CTkButton(modal, text="done")
        done_button.grid(padx=5, pady=5) 

        important = ctk.CTkLabel(modal, text = "ATENTION: The router time zone is GMT", text_color="red")
        important.grid(pady=10)


    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        filemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=filemenu)
        filemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))
        filemenu.add_command(label="Managed devices", command=lambda: parent.show_frame(parent.ManagedDevices))
  
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar


if __name__ == "__main__":
    with app.app_context():
        App().mainloop()
        

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
        self.GeneralRules = GeneralRules

        ## Defining Frames and Packing it
        for F in {LoginPage, SignupPage, RouterDataPage, HomePage, ManagedDevices, Settings, DeviceSettings, GeneralRules}:
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

        signup_button = ctk.CTkButton(self, text = "Sign up", cursor = 'hand2', command = lambda: parent.show_frame(parent.SignupPage))
        signup_button.pack(pady = 1, padx = 10)

        def login(username, password):
            username = username_entry.get()
            password = password_entry.get()
            user_data = user.query.filter_by(username=username).first()
            if user_data:
                stored_password = user_data.password
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    self.get_iduser(username)
                    parent.show_frame(parent.RouterDataPage)
                else:
                    messagebox.showerror("Login Failed", "Incorrect password.")
            else:
                messagebox.showerror("Login Failed", "Username not found.")

    def get_iduser(self, username):
        global id_connected_user
        connected_user = db.session.query(user).filter_by(username=username).first()
        id_connected_user = connected_user.iduser



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
            global credentials_saved
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
                client.connect(hostname=host, username=username, password=password, auth_timeout=4, timeout=4) 
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
        label.grid(row = 0, column = 0, columnspan = 2, sticky = N, pady = 20, padx = 10)

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
            print("The JSON file wasn't found")
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

        devicemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=devicemenu)
        devicemenu.add_command(label="Managed devices", command=lambda: parent.show_frame(parent.ManagedDevices))

        setttingsmenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Settings", menu=setttingsmenu)
        setttingsmenu.add_command(label="New", command=lambda: parent.show_frame(parent.Settings)) 
        setttingsmenu.add_command(label="General rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
        setttingsmenu.add_command(label="Usual rules", command=lambda: parent.show_frame(parent.GeneralRules)) 

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
        label.grid(column = 0, row = 0, columnspan = 2, sticky = N, pady = 20, padx = 10)

        devices = db.session.query(device.device_name, device.MAC_address, device.device_type).all()
        for i, dev in enumerate(devices):
            device_data = f"{dev.device_name}\nMAC address: {dev.MAC_address}\nDevice type: {dev.device_type}"

            label = ctk.CTkLabel(self, text=device_data)
            label.grid(row=i+1, column=0, sticky=E, pady=45, padx=10)

            edit_button = ctk.CTkButton(self, text="edit", command= lambda dev = dev : self.edit_device(dev))
            edit_button.grid(row=i+1, column=1, sticky = NW, pady=55, padx=10)


        self.after(5000, self.get_and_show_devices, parent)

    def edit_device(self, dev):
        parent_container = self.master
        edit_frame = DeviceSettings(self.parent_window, parent_container,  device_info = dev)
        edit_frame.grid(row=0, column=0, sticky = "nsew")


    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        devicemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=devicemenu)
        devicemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))

        setttingsmenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Settings", menu=setttingsmenu)
        setttingsmenu.add_command(label="New", command=lambda: parent.show_frame(parent.Settings)) 
        setttingsmenu.add_command(label="General rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
        setttingsmenu.add_command(label="Usual rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
 
        ## help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit) 

        return menubar

#---------------------------------------------------DEVICE SETTINGS FRAME / CONTAINER --------------------------------------------------
def get_firewall_rules(mac=None):
        try: 
            with open('router_data.json') as data_file:
               router_data = json.load(data_file)
            host = router_data['ip_address']
            username = router_data['router_user']
            password = router_data['router_password']

            command = "uci show firewall"
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, username=username, password=password)
            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            client.close()
            output = output.strip().split('\n')
            rules = defaultdict(dict)
            rule_components = re.compile(r'firewall\.@(\w+)\[(\d+)\]\.(\w+)=(.+)')

            for line in output:
                match = rule_components.match(line)
                if match:
                    rule_type, index, key, value = match.groups()
                    full_key = f"{rule_type}_{index}"
                    if 'rule' in full_key:
                        rules[full_key][key] = value.strip("'")

            rules_with_index = []
            for key, attributes in rules.items():
                rule_type, index = key.split('_')
                attributes['rule'] = int(index)
                rules_with_index.append(attributes)

            with open('active_rules.json', 'w') as f:
                json.dump(rules_with_index, f, indent=4)

            # rules_without_index = [ {k: v for k, v in attributes.items() if k != 'rule'} for attributes in rules_with_index]
            filtered_rules = []

            for rule in rules_with_index:
                if mac is None:
                    if 'src_mac' not in rule and rule["rule"] > 8 :
                        filtered_rules.append(rule)
                else:
                    if rule.get('src_mac') == mac:
                        filtered_rules.append(rule)
            return filtered_rules
        except FileNotFoundError:
            print("The JSON file wasn't found")

import re
from collections import defaultdict
class DeviceSettings(ctk.CTkFrame):
    def __init__(self, parent, container, device_info = ("", "", ""), *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        global scrollable_frame
        scrollable_frame = ctk.CTkScrollableFrame(self)
        scrollable_frame.pack(fill='both', expand=True)
        scrollable_frame.columnconfigure(0, weight=1)
        scrollable_frame.columnconfigure(1, weight=1)
        self.parent = parent
        self.device_info = device_info
        self.show_device_settings()

    def show_device_settings(self):
        
        for widget in scrollable_frame.grid_slaves():
            widget.grid_remove()

        back_button = ctk.CTkButton(scrollable_frame, text = "\u2190", command=lambda: self.parent.show_frame(ManagedDevices), text_color = "white", fg_color = "transparent", hover_color = "#544D4D")
        back_button.grid(row = 0, column = 1, sticky = "ne", padx=10, pady=10)
        title = ctk.CTkLabel(scrollable_frame, text="Device Settings")
        title.grid(row = 1, column = 0, pady = 5, padx = 10, columnspan = 2, sticky = "n")
        # global mac_address
        # Extract the device name, MAC address, and device type from the device_info tuple
        device_name, mac_address, device_type = self.device_info

        # Create an entry for the device name
        devicename_entry = ctk.CTkEntry(scrollable_frame, width = max(len(device_name) * 7, 150))
        devicename_entry.insert(0, device_name)
        devicename_entry.grid(row = 2, column = 0, pady=10, columnspan = 2, sticky = "n")

        # Create a label for the MAC address
        mac_label = ctk.CTkLabel(scrollable_frame, text=f"MAC Address: {mac_address}")
        mac_label.grid(row = 3, column = 0, pady=5, columnspan = 2, sticky = "n")

        # Create a dropdown menu for selecting device type
        device_type_var = ctk.StringVar(scrollable_frame)
        device_type_var.set(device_type)
        device_types = ['Router', 'Extender', 'Mobile', 'Laptop', 'Computer', 'TV', 'Other']
        device_type_dropdown = ctk.CTkOptionMenu(scrollable_frame, variable=device_type_var, values=device_types)
        device_type_dropdown.grid(row = 4, column = 0, pady=5, columnspan = 2, sticky = "n")

        delete_button = ctk.CTkButton(scrollable_frame, fg_color="transparent", hover_color="#F24A3B", text="delete", command = lambda: delete(mac_address, self.parent))
        delete_button.grid(row = 5, column = 0, pady = 5, columnspan = 2, sticky = "n")

        done_button = ctk.CTkButton(scrollable_frame, text="done", command = lambda: edit_device(self.parent, devicename_entry, mac_address, device_type_dropdown))
        done_button.grid(row = 6, column = 0, padx=5, pady=5, columnspan = 2, sticky = "n")

        title2 = ctk.CTkLabel(scrollable_frame, text = "ACTIVE RULES")
        title2.grid(row = 7, column = 0, pady=15, columnspan = 2, sticky = "n")

        active_rules = get_firewall_rules(mac_address)
    
        try:
            rules_without_index = [ {k: v for k, v in attributes.items() if k != 'rule'} for attributes in active_rules]
            for i, rule in enumerate(rules_without_index):
                rule_str = "\n".join([f"{key}: {value}" for key, value in rule.items()])
                rule_label = ctk.CTkLabel(scrollable_frame, text=rule_str, width=350)
                rule_label.grid(row=8+i, column=0, sticky = E, pady=15, padx=10)
            for i, rule in enumerate(active_rules):
                button = ctk.CTkButton(scrollable_frame, text="edit rule", command = lambda rule = rule : edit_rules_modal(self, rule, mac_address))
                button.grid(row=8+i, column=1, sticky = W, pady=5, padx=10)
        except:
            print("first time loading")

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
                existing_device.device_name = device_name
                existing_device.device_type = device_type
                db.session.commit()
            parent.show_frame(ManagedDevices)

    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        devicemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=devicemenu)
        devicemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))

        setttingsmenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Settings", menu=setttingsmenu)
        setttingsmenu.add_command(label="New", command=lambda: parent.show_frame(parent.Settings)) 
        setttingsmenu.add_command(label="General rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
        setttingsmenu.add_command(label="Usual rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
 
        ## help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit) 

        return menubar
    
def edit_rules_modal(self, rule, mac = None):
        modal = ctk.CTkToplevel(self.parent)
        modal.configure(bg="#333333")
        modal.title("Setting")
        modal.geometry("250x250")

        # Calculate the position relative to the parent window
        parent_x = self.parent.winfo_rootx()
        parent_y = self.parent.winfo_rooty()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()

        modal_x = parent_x + parent_width // 2 + 380  # Position the modal horizontally
        modal_y = parent_y + parent_height // 2 - 300  # Position the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent)
        # Grab the focus to the modal window
        modal.grab_set()

        scrollable_frame = ctk.CTkScrollableFrame(modal)
        scrollable_frame.pack(fill='both', expand=True)

        title = ctk.CTkLabel(scrollable_frame, text = "Edit Setting")
        title.grid(column = 0, columnspan = 2, sticky = N ,pady = 5)

        label = ctk.CTkLabel(scrollable_frame, text = "Rule Name:")
        label.grid(column = 0, pady = 10, sticky = "W")

        rule_name = rule["name"].split("@")[1]

        name_entry = ctk.CTkEntry(scrollable_frame)
        name_entry.insert(0, rule_name)
        name_entry.grid(column = 0, sticky="nsew")

        mac_label = ctk.CTkLabel(scrollable_frame, text = f"Mac address: {mac}")
        mac_label.grid(column = 0, pady = 10, sticky = "W")

        ip_value = rule.get("dest_ip")
        if ip_value:
            modal.geometry("220x240")
            ip_list = ip_value.split(" ")
            try:               
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)
                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                addresses_list = []
                for ip in ip_list:
                    ip_command = f"nslookup {ip} | awk '/name =/ {{ print $4 }}'"
                    stdin, stdout, stderr = client.exec_command(ip_command)
                    website = stdout.read().decode()
                    addresses_list.append(website)
                websites = ", ".join(addresses_list)
                client.close()
            except FileNotFoundError:
                print("The JSON file wasn't found")
            if rule["target"] == "REJECT":
                label = ctk.CTkLabel(scrollable_frame, text = "Blocked websites:")
                label.grid(column = 0, pady = 5, sticky = "W")
            if rule["target"] == "ACCEPT":
                label = ctk.CTkLabel(scrollable_frame, text = "Allowed websites:")
                label.grid(column = 0, pady = 5, sticky = "W")
            websites_entry = ctk.CTkEntry(scrollable_frame)
            websites_entry.insert(0, websites)
            websites_entry.grid(column = 0, sticky="nsew")
        
        start = rule.get("start_time")
        stop = rule.get("stop_time")

        label_start = ctk.CTkLabel(scrollable_frame, text = "Start time: (hh:mm:ss)")
        label_start.grid(column = 0, pady = 5, sticky = "W")
        start_entry = ctk.CTkEntry(scrollable_frame)
        start_entry.grid(column = 0, sticky="nsew")
        label_stop = ctk.CTkLabel(scrollable_frame, text = "Stop time: (hh:mm:ss)")
        label_stop.grid(column = 0, pady = 5, sticky = "W")
        stop_entry = ctk.CTkEntry(scrollable_frame)
        stop_entry.grid(column = 0, sticky="nsew")
        important = ctk.CTkLabel(scrollable_frame, text = "ATENTION: The router time zone is GMT", text_color="red")
        important.grid(pady=5, sticky = "N")
        if start and stop:
            start_entry.insert(0, start) 
            stop_entry.insert(0, stop) 
        days = rule.get("weekdays")
        affected_days = StringVar(value=days)
        if days:
            days_label = ctk.CTkLabel(scrollable_frame, text="Restriction days")
            days_label.grid(padx=5, pady=12, sticky=tk.W)

            weekdays_dict = {1: "Mon", 2: "Tue", 3: "Wed", 4: "Thu", 5: "Fri", 6: "Sat", 7: "Sun"}
            weekdays_listbox = CTkListbox(scrollable_frame, multiple_selection=True)
            for key, value in weekdays_dict.items():
                weekdays_listbox.insert(tk.END, value)
            selected_days = affected_days.get().split(" ")
            if isinstance(selected_days, list):
                for day in selected_days:
                    if day in weekdays_dict.values():
                        index = list(weekdays_dict.values()).index(day)
                        weekdays_listbox.activate(index)            
            weekdays_listbox.grid(sticky=tk.NSEW)

        rule_number = rule["rule"]
        
        edit_button = ctk.CTkButton(scrollable_frame, text="edit", command = lambda : edit_setting())
        edit_button.grid(pady = 10)

        delete_button = ctk.CTkButton(scrollable_frame, fg_color="transparent", hover_color="#F24A3B", text="delete", command = lambda : delete_setting())
        delete_button.grid(pady = 5)

        start_index = rule["name"].index('-') + 1
        end_index = rule["name"].index('@')
        iddevice_setting = rule["name"][start_index:end_index]
        existing_setting = device_setting.query.filter_by(iddevice_setting = iddevice_setting).first()

        def edit_setting():
            # existing_setting = device_setting.query.filter_by(rule_number = rule_number).first()
            # print("existing setting:", existing_setting)
            # if existing_setting:
            #     setting_value = existing_setting.setting_value
            #     print(setting_value)
            name = name_entry.get()
            if existing_setting:
                setting_value = existing_setting.setting_value
                new_name = f"SafeNet-{iddevice_setting}@{name}"
            new_stop = stop_entry.get()
            new_start = start_entry.get()
            try:               
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)
                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                if rule_name != new_name:
                    change_name = f"uci set firewall.@rule[{rule_number}].name='{new_name}'"
                    execute_command(client, change_name)
                    setting_value["rule name"] = new_name
                    print(setting_value)
                    existing_setting.setting_value = setting_value   
                if start:
                    if start != new_start:
                        if len(new_start) != 8:
                            messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                            return
                        else:
                            change_start = f"uci set firewall.@rule[{rule_number}].start_time='{new_start}'"
                            execute_command(client, change_start)
                            existing_setting.start_time = new_start
                elif new_start:
                    if len(new_start) != 8:
                        messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                        return
                    else:
                        add_start = f"uci set firewall.@rule[{rule_number}].start_time='{new_start}'"
                        execute_command(client, add_start)
                        existing_setting.start_time = new_start
                if stop:
                    if stop != new_stop:
                        if len(new_stop) != 8:
                            messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                            return
                        else:
                            change_stop = f"uci set firewall.@rule[{rule_number}].stop_time='{new_stop}'"
                            execute_command(client, change_stop)
                            existing_setting.end_time = new_stop
                elif new_stop:
                    if len(new_stop) != 8:
                        messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                        return
                    else:
                        add_stop = f"uci set firewall.@rule[{rule_number}].stop_time='{new_stop}'"
                        execute_command(client, add_stop)
                        existing_setting.end_time = new_stop  
                if days:
                    new_weekdays = weekdays_listbox.get()
                    weekdays_str = " ".join(new_weekdays)
                    if selected_days != new_weekdays:
                        change_weekdays = f"uci set firewall.@rule[{rule_number}].weekdays='{weekdays_str}'"
                        execute_command(client, change_weekdays)
                        setting_value["affected days"] = weekdays_str
                        print(setting_value)
                        existing_setting.setting_value = setting_value
                if ip_value:
                    new_websites = websites_entry.get().strip().split(",")
                    new_websites = [ip.strip() for ip in new_websites]
                    ip_list = ip_value.split(" ")
                    print(ip_list)
                    addresses_list = []
                    for website in new_websites:
                        ip_command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"
                        ip_address = execute_command(client, ip_command)
                        first_ip_address = ip_address.split('\n')[0].strip()
                        addresses_list.append(first_ip_address)
                        addresses = " ".join(addresses_list)
                    if ip_list != addresses_list:
                        change_websites = f"uci set firewall.@rule[{rule_number}].dest_ip='{addresses}'\n"
                        execute_command(client, change_websites)
                        setting_value["websites"] = addresses
                        print(setting_value)
                        existing_setting.setting_value = setting_value
                    else:
                        print("same websites as before")
                final_command = """uci commit firewall
                                   service firewall restart"""
                execute_command(client, final_command)
                client.close()
                db.session.commit()
                print("Changes committed to the database")
                modal.destroy()
                calling_class = self.__class__.__name__
                if calling_class == "DeviceSettings":
                    self.show_device_settings()
                if calling_class == "GeneralRules":
                   self.show_general_rules()
            except FileNotFoundError:
                print("The JSON file wasn't found")

        def delete_setting():
            try:               
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)
                command = f"""uci delete firewall.@rule[{rule_number}]
                            uci commit firewall
                            service firewall restart"""
                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                client.exec_command(command)
                client.close()
                if existing_setting:
                    db.session.delete(existing_setting)
                    db.session.commit()
                modal.destroy()    
                calling_class = self.__class__.__name__
                if calling_class == "DeviceSettings":
                    self.show_device_settings()
                if calling_class == "GeneralRules":
                   self.show_general_rules()
            except FileNotFoundError:
                print("The JSON file wasn't found")

#---------------------------------------------------SETTINGS FRAME / CONTAINER --------------------------------------------------
from functools import partial
from db_creation import settings
from tkinter import ttk
from CTkListbox import CTkListbox
from db_creation import device_setting
from datetime import datetime
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
        self.get_idsetting(setting_name)
        modal_functions = {
            "Manage Access to Wi-fi": self.manage_access_modal,
            "Network Usage Scheduler": self.time_restriction_modal,
            "Block Access to Website": self.block_website_modal,
            "Block all access except for some websites": self.allow_only_some_websites
        }

        modal_function = modal_functions.get(setting_name)

        if modal_function:
            modal_function()
        else:
            print("Modal function not found for setting:", setting_name)
    
    def get_idsetting(self, setting_name):
        global id_selected_setting
        selected_setting = db.session.query(settings).filter(settings.setting_name == setting_name).first()
        id_selected_setting = selected_setting.idsetting


    def manage_access_modal(self):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Setting")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 + 380  # Position the modal horizontally
        modal_y = parent_y + parent_height // 2 - 300  # Position the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        scrollable_frame = ctk.CTkScrollableFrame(modal)
        scrollable_frame.pack(fill='both', expand=True)
        title = ctk.CTkLabel(scrollable_frame, text = "Manage access to Wi-fi")
        title.grid(pady = 5)

        label = ctk.CTkLabel(scrollable_frame, text = "Select the desired action:")
        label.grid(pady=10)

        actions = ["deny", "allow"]
        action_option = ctk.CTkOptionMenu(scrollable_frame, values=actions)
        action_option.grid(pady=0)

        devices = db.session.query(device.device_name, device.MAC_address).all()
        device_info = {name: mac for name, mac in devices}

        def on_device_selected(event):
                    global selected_mac_address
                    selected_device = device_dropdown.get()
                    selected_mac_address = device_info.get(selected_device)
                    
                    if selected_mac_address:
                        mac_label.configure(text=f"MAC Address: {selected_mac_address}")

                    else:
                        print("MAC address not found for device:", selected_device)
        
        device_dropdown = ttk.Combobox(scrollable_frame, values=list(device_info.keys()), width = 30, state = "readonly")
        device_dropdown.set("Select Device")
        device_dropdown.grid(padx=10, pady=10)

        mac_label = ctk.CTkLabel(scrollable_frame, text="MAC Address: ")
        mac_label.grid(padx=10, pady=10)

        device_dropdown.bind("<<ComboboxSelected>>", on_device_selected)

        done_button = ctk.CTkButton(scrollable_frame, text = "Done", command = lambda: block_wifi_access(action_option,selected_mac_address))
        done_button.grid(pady = 10)

        def block_wifi_access(action, src_mac):
            action = action_option.get()
            setting_value = {"enabled": True,
                             "action": action}
            setting_time = datetime.now()
            affected_device = db.session.query(device).filter(device.MAC_address == src_mac).first()
            id_affected_device = affected_device.iddevice
            try:
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)

                command = f"""uci set wireless.@wifi-iface[0].macfilter={action}
                              uci add_list wireless.@wifi-iface[0].maclist={src_mac}
                              uci show wireless.@wifi-iface[0]
                              uci commit wireless
                              wifi reload"""
                
                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                client.exec_command(command)
                client.close()
            except FileNotFoundError:
                print("The JSON file wasn't found")
            self.save_devicesetting(id_connected_user, id_affected_device, id_selected_setting, setting_value, setting_time, start_time = None, end_time = None)
            modal.destroy()


    def time_restriction_modal(self):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Setting")
        modal.geometry("250x500")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 + 380  # Position the modal horizontally
        modal_y = parent_y + parent_height // 2 - 300  # Position the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        scrollable_frame = ctk.CTkScrollableFrame(modal)
        scrollable_frame.pack(fill='both', expand=True)

        title = ctk.CTkLabel(scrollable_frame, text = "Time Restriction Setting")
        title.grid(pady = 5, sticky = "N")

        label = ctk.CTkLabel(scrollable_frame, text = "Rule Name:")
        label.grid(padx = 5, pady = 10, sticky = "W")

        setting_name = "Filter-Parental-Controls"
        settingname_entry = ctk.CTkEntry(scrollable_frame)
        settingname_entry.insert(0, setting_name)
        settingname_entry.grid(padx = 5, sticky=NSEW)

        src = "lan"
        source = ctk.CTkLabel(scrollable_frame, text = f"Source zone: {src}")
        source.grid(pady=5, sticky = "N")

        devices = db.session.query(device.device_name, device.MAC_address).all()
        device_info = {name: mac for name, mac in devices}

        selected_mac_address = None

        def on_device_selected(event):
            nonlocal selected_mac_address
            selected_device = device_dropdown.get()
            selected_mac_address = device_info.get(selected_device)
            if selected_mac_address:
                mac_label.configure(text=f"MAC Address: {selected_mac_address}")
            else:
                print("MAC address not found for device:", selected_device)
        
        device_dropdown = ttk.Combobox(scrollable_frame, values=list(device_info.keys()), width = 30, state = "readonly")
        device_dropdown.set("Select Device")
        device_dropdown.grid(padx=10, pady=10, sticky = "N")

        mac_label = ctk.CTkLabel(scrollable_frame, text="MAC Address: ")
        mac_label.grid(padx=10, pady=10, sticky = "N")

        device_dropdown.bind("<<ComboboxSelected>>", on_device_selected)

        dest = "wan"
        destination = ctk.CTkLabel(scrollable_frame, text = f"Destination zone: {dest}")
        destination.grid(pady=10, sticky = "N")

        start_time = ctk.CTkEntry(scrollable_frame, placeholder_text = "Start Time (hh:mm:ss)")
        start_time.grid(pady = 12, sticky = "N")

        stop_time = ctk.CTkEntry(scrollable_frame, placeholder_text = "Stop Time (hh:mm:ss)")
        stop_time.grid(pady = 12, sticky = "N")

        select_days_label = ctk.CTkLabel(scrollable_frame, text = "Select the restriction days")
        select_days_label.grid(padx= 5, pady= 12, sticky = W)

        weekdays_dict = {1: "Monday", 2: "Tuesday", 3: "Wednesday", 4: "Thursday", 5: "Friday", 6: "Saturday", 7: "Sunday"}
        weekdays_listbox = CTkListbox(scrollable_frame, multiple_selection = True)
        for key, value in weekdays_dict.items():
            weekdays_listbox.insert(tk.END, value)
        weekdays_listbox.grid(sticky=tk.NSEW)

        target = "REJECT"
        action = ctk.CTkLabel(scrollable_frame, text = f"Action: {target}")
        action.grid(pady=10, sticky = "N")

        done_button = ctk.CTkButton(scrollable_frame, text="Submit", command = lambda : time_restriction_setting(settingname_entry,src,selected_mac_address,dest,start_time,stop_time,weekdays_listbox,target))
        done_button.grid(padx=5, pady=5, sticky = "N") 

        important = ctk.CTkLabel(scrollable_frame, text = "ATENTION: The router time zone is GMT", text_color="red")
        important.grid(pady=10, sticky = "N")

        def time_restriction_setting(name,src,mac,dest,start,stop,days,target):
            name = settingname_entry.get()
            start = start_time.get()
            stop = stop_time.get()
            days = weekdays_listbox.get()
            setting_time = datetime.now()
            try:
                short_days = ' '.join([day[:3] for day in days])
                setting_value = {   "rule name": name,
                                    "affected days": short_days,
                                    "enabled": True}
            except:
                messagebox.showerror("Error", "Please select the affected days")
            try:
                affected_device = db.session.query(device).filter(device.MAC_address == mac).first()
                id_affected_device = affected_device.iddevice
            except:
                messagebox.showerror("Error", "Please select a device")
            if len(start) != 8 or len(stop) != 8:
                messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                return
            
            try:
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)
                
                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                id_devicesetting = self.save_devicesetting(id_connected_user, id_affected_device, id_selected_setting, setting_value, setting_time, start, stop)
                rule_name = f"SafeNet-{id_devicesetting}@{name}"

                command = f"""uci add firewall rule
                            uci set firewall.@rule[-1].name={rule_name}
                            uci set firewall.@rule[-1].src={src}
                            uci set firewall.@rule[-1].src_mac={mac}
                            uci set firewall.@rule[-1].dest={dest}
                            uci set firewall.@rule[-1].start_time={start}
                            uci set firewall.@rule[-1].stop_time={stop}
                            uci set firewall.@rule[-1].weekdays="{short_days}"
                            uci set firewall.@rule[-1].target={target}
                            uci commit firewall
                            service firewall restart"""
                execute_command(client, command)
                # rule_number = get_rule_number(client, -1)
                client.close()
            except FileNotFoundError:
                print("The JSON file wasn't found")
            modal.destroy()

    def block_website_modal(self):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Setting")
        modal.geometry("300x300")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 + 380  # Position the modal horizontally
        modal_y = parent_y + parent_height // 2 - 300  # Position the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        scrollable_frame = ctk.CTkScrollableFrame(modal)
        scrollable_frame.pack(fill='both', expand=True)

        title = ctk.CTkLabel(scrollable_frame, text = "Block access to website")
        title.grid(pady = 5)

        label = ctk.CTkLabel(scrollable_frame, text = "Rule Name:")
        label.grid(padx = 5, pady = 10, sticky = "W")

        setting_name = "Block websites"
        settingname_entry = ctk.CTkEntry(scrollable_frame)
        settingname_entry.insert(0, setting_name)
        settingname_entry.grid(padx = 5, sticky=NSEW)

        label = ctk.CTkLabel(scrollable_frame, text = "Enter websites to block (separated by comma):")
        label.grid(pady=10)

        websites_entry = ctk.CTkEntry(scrollable_frame)
        websites_entry.grid(sticky=NSEW)

        devices = db.session.query(device.device_name, device.MAC_address).all()
        device_info = {name: mac for name, mac in devices}

        selected_mac_address = None

        def on_device_selected(event):
            nonlocal selected_mac_address
            selected_device = device_dropdown.get()
            selected_mac_address = device_info.get(selected_device)
            if selected_mac_address:
                mac_label.configure(text=f"MAC Address: {selected_mac_address}")
            else:
                print("MAC address not found for device:", selected_device)
        
        device_dropdown = ttk.Combobox(scrollable_frame, values=list(device_info.keys()), width = 30, state = "readonly")
        device_dropdown.set("Select Device")
        device_dropdown.grid(padx=10, pady=10)

        mac_label = ctk.CTkLabel(scrollable_frame, text="MAC Address: ")
        mac_label.grid(padx=10, pady=10)

        device_dropdown.bind("<<ComboboxSelected>>", on_device_selected)

        start_time = ctk.CTkEntry(scrollable_frame, placeholder_text = "Start Time (hh:mm:ss)")
        start_time.grid(pady = 12, sticky = "N")

        stop_time = ctk.CTkEntry(scrollable_frame, placeholder_text = "Stop Time (hh:mm:ss)")
        stop_time.grid(pady = 12, sticky = "N")

        done_button = ctk.CTkButton(scrollable_frame, text = "Submit", command = lambda: block_website_access(settingname_entry, selected_mac_address))
        done_button.grid(pady = 10)

        important = ctk.CTkLabel(scrollable_frame, text = "ATENTION: The router time zone is GMT", text_color="red")
        important.grid(pady=10, sticky = "N")

        def block_website_access(rule_name, src_mac):
            start = start_time.get()
            stop = stop_time.get()
            name = settingname_entry.get()
            websites = websites_entry.get().strip().split(",")
            setting_value = {   "rule name": name,
                                "websites": ", ".join(websites),
                                "enabled": True
                             }
            setting_time = datetime.now()
            try:
                affected_device = db.session.query(device).filter(device.MAC_address == src_mac).first()
                id_affected_device = affected_device.iddevice
            except:
                messagebox.showerror("Error", "Please select a device")
            if start and stop:
                if len(start) != 8 or len(stop) != 8:
                    messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                    return
            if websites == [""]:
                messagebox.showerror("Error", "Please enter at least one website to block.")
                return
            
            try:               
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)
                
                # command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"

                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                id_devicesetting = self.save_devicesetting(id_connected_user, id_affected_device, id_selected_setting, setting_value, setting_time, start, stop)
                rule_name = f"SafeNet-{id_devicesetting}@{name}"
                addresses_list = []
                for website in websites:
                    ip_command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"
                    ip_address = execute_command(client, ip_command)
                    first_ip_address = ip_address.split('\n')[0].strip()
                    addresses_list.append(first_ip_address)
                    addresses = " ".join(addresses_list)
                firewall_command = "uci add firewall rule\n"
                firewall_command += f"uci set firewall.@rule[-1].name='{rule_name}'\n"
                firewall_command += "uci set firewall.@rule[-1].src='lan'\n"
                firewall_command += f"uci set firewall.@rule[-1].src_mac='{src_mac}'\n"
                firewall_command += f"uci set firewall.@rule[-1].dest_ip='{addresses}'\n"
                firewall_command += "uci set firewall.@rule[-1].dest='wan'\n"
                if start and stop :
                    firewall_command += f"uci set firewall.@rule[-1].start_time={start}\n"
                    firewall_command += f"uci set firewall.@rule[-1].stop_time={stop}\n"
                firewall_command += "uci set firewall.@rule[-1].proto='all'\n"
                firewall_command += "uci set firewall.@rule[-1].target='REJECT'\n"
                firewall_command += "uci commit firewall\n"
                firewall_command += "service firewall restart\n"

                execute_command(client, firewall_command)
                # rule_number = get_rule_number(client, -1)
                client.close()
                modal.destroy()
            except FileNotFoundError:
                print("The JSON file wasn't found")

    def allow_only_some_websites(self):
        modal = ctk.CTkToplevel(self.parent_window)
        modal.configure(bg="#333333")
        modal.title("Setting")
        modal.geometry("360x350")

        # Calculate the position relative to the parent window
        parent_x = self.parent_window.winfo_rootx()
        parent_y = self.parent_window.winfo_rooty()
        parent_width = self.parent_window.winfo_width()
        parent_height = self.parent_window.winfo_height()

        modal_x = parent_x + parent_width // 2 + 380  # Position the modal horizontally
        modal_y = parent_y + parent_height // 2 - 300  # Position the modal vertically
        modal.geometry(f"+{modal_x}+{modal_y}")

        # Make the modal window transient to the parent window
        modal.transient(self.parent_window)
        # Grab the focus to the modal window
        modal.grab_set()

        scrollable_frame = ctk.CTkScrollableFrame(modal)
        scrollable_frame.pack(fill='both', expand=True)

        title = ctk.CTkLabel(scrollable_frame, text = "Block all internet access but to some websites")
        title.grid(pady = 5)

        label = ctk.CTkLabel(scrollable_frame, text = "Rule Name:")
        label.grid(padx = 5, pady = 10, sticky = "W")

        setting_name = "Allow only some websites"
        settingname_entry = ctk.CTkEntry(scrollable_frame)
        settingname_entry.insert(0, setting_name)
        settingname_entry.grid(padx = 5, sticky=NSEW)

        label = ctk.CTkLabel(scrollable_frame, text = "Please enter the allowed websites (separated by comma):")
        label.grid(padx = 5, pady=10)

        websites_entry = ctk.CTkEntry(scrollable_frame)
        websites_entry.grid(sticky=NSEW)

        selected_mac = None

        devices = db.session.query(device.device_name, device.MAC_address).all()
        device_info = {name: mac for name, mac in devices}

        def on_device_selected(event):
            nonlocal selected_mac
            selected_device = device_dropdown.get()
            selected_mac = device_info.get(selected_device, "")
            print("Selected MAC Address:", selected_mac)
            if selected_mac:
                mac_label.configure(text=f"MAC Address: {selected_mac}")
            else:
                print("MAC address not found for device:", selected_device)
        
        label = ctk.CTkLabel(scrollable_frame, text = "Select a device if the rule is intented for a specific device")
        label.grid(pady=10)
        device_dropdown = ttk.Combobox(scrollable_frame, values=list(device_info.keys()), width = 30, state = "readonly")
        device_dropdown.set("Select")
        device_dropdown.grid(padx=10, pady=0)

        mac_label = ctk.CTkLabel(scrollable_frame, text="MAC Address: ")
        mac_label.grid(padx=10, pady=10)

        device_dropdown.bind("<<ComboboxSelected>>", on_device_selected)

        start_time = ctk.CTkEntry(scrollable_frame, placeholder_text = "Start Time (hh:mm:ss)")
        start_time.grid(pady = 12, sticky = "N")

        stop_time = ctk.CTkEntry(scrollable_frame, placeholder_text = "Stop Time (hh:mm:ss)")
        stop_time.grid(pady = 12, sticky = "N")

        done_button = ctk.CTkButton(scrollable_frame, text = "Submit", command = lambda: allow_websites(selected_mac))
        done_button.grid(pady = 10)

        important = ctk.CTkLabel(scrollable_frame, text = "ATENTION: The router time zone is GMT", text_color="red")
        important.grid(pady=10, sticky = "N")

        def allow_websites(selected_mac):
            name = settingname_entry.get()
            start = start_time.get()
            stop = stop_time.get()
            websites = websites_entry.get().strip().split(",")
            setting_value_websites = {  "rule name": name,
                                        "websites": ", ".join(websites),
                                        "enabled": True
                                        }
            setting_value_block = {     "rule name": "Block all access",
                                        "enabled": True
                                        }
            setting_time = datetime.now()
            id_affected_device = None
            if start and stop:
                if len(start) != 8 or len(stop) != 8:
                    messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                    return
            if websites == [""]:
                messagebox.showerror("Error", "Please enter at least one website")
                return
            if selected_mac:
                affected_device = db.session.query(device).filter(device.MAC_address == selected_mac).first()
                id_affected_device = affected_device.iddevice

            # existing_setting1 = device.query.filter_by(MAC_address =id_devicesetting1).first()
            # existing_setting2 = device.query.filter_by(MAC_address =id_devicesetting2).first()
            # if existing_setting1:
            #     existing_setting1.rule_name = rule_name_websites
            #     db.session.commit()
            # elif existing_setting2:
            #     existing_setting2.rule_name = rule_name_websites
            #     db.session.commit()
            try:               
                with open('router_data.json') as data_file:
                    router_data = json.load(data_file)

                host = router_data['ip_address']
                username = router_data['router_user']
                password = router_data['router_password']
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, username=username, password=password)
                id_devicesetting1 = self.save_devicesetting(id_connected_user, id_affected_device, id_selected_setting, setting_value_websites, setting_time, None, None)
                id_devicesetting2 = self.save_devicesetting(id_connected_user, id_affected_device, id_selected_setting, setting_value_block, setting_time, start, stop)
                rule_name_websites = f"SafeNet-{id_devicesetting1}@{name}"
                rule_name_block = f"SafeNet-{id_devicesetting2}@Block all access"
                addresses_list = []
                for website in websites:
                    ip_command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"
                    ip_address = execute_command(client, ip_command)
                    first_ip_address = ip_address.split('\n')[0].strip()
                    addresses_list.append(first_ip_address)
                    addresses = " ".join(addresses_list)
                firewall_command = "uci add firewall rule\n"
                firewall_command += f"uci set firewall.@rule[-1].name='{rule_name_websites}'\n"
                firewall_command += "uci set firewall.@rule[-1].src='lan'\n"
                if selected_mac:
                    firewall_command += f"uci set firewall.@rule[-1].src_mac='{selected_mac}'\n"
                firewall_command += "uci set firewall.@rule[-1].dest='wan'\n"
                firewall_command += f"uci set firewall.@rule[-1].dest_ip='{addresses}'\n"
                firewall_command += "uci set firewall.@rule[-1].target='ACCEPT'\n"
                firewall_command += "uci commit firewall\n"
                firewall_command += "uci add firewall rule\n"
                firewall_command += f"uci set firewall.@rule[-1].name='{rule_name_block}'\n"
                firewall_command += "uci set firewall.@rule[-1].src='lan'\n"
                if selected_mac:
                    firewall_command += f"uci set firewall.@rule[-1].src_mac='{selected_mac}'\n"
                firewall_command += "uci set firewall.@rule[-1].dest='wan'\n"
                if start and stop :
                    firewall_command += f"uci set firewall.@rule[-1].start_time={start}\n"
                    firewall_command += f"uci set firewall.@rule[-1].stop_time={stop}\n"
                firewall_command += "uci set firewall.@rule[-1].target='REJECT'\n"
                firewall_command += "uci commit firewall\n"
                firewall_command += "service firewall restart\n" 
                execute_command(client, firewall_command)
                # rule_number_websites = get_rule_number(client, -2)
                # rule_number_block_access = get_rule_number(client, -1)
                client.close()
                modal.destroy()
            except FileNotFoundError:
                print("The JSON file wasn't found")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
       

    def save_devicesetting(self, iduser, iddevice, idsetting, setting_value, setting_time, start_time, end_time):
            new_device_setting = device_setting(iduser=iduser, iddevice=iddevice, idsetting=idsetting, setting_value=setting_value, setting_time=setting_time, start_time=start_time, end_time = end_time)
            db.session.add(new_device_setting)
            db.session.commit()
            id_devicesetting = new_device_setting.iddevice_setting
            return id_devicesetting


    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        devicemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=devicemenu)
        devicemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))
        devicemenu.add_command(label="Managed devices", command=lambda: parent.show_frame(parent.ManagedDevices))

        setttingsmenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Settings", menu=setttingsmenu)
        setttingsmenu.add_command(label="General rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
        setttingsmenu.add_command(label="Usual rules", command=lambda: parent.show_frame(parent.GeneralRules)) 
  
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar
    
def execute_command(client, command):
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode()

def get_rule_number(client, rule_position):
    command = "uci show firewall | grep '=rule'"
    rules_str = execute_command(client, command)
    lines = rules_str.strip().split('\n')
    rule_line = lines[rule_position]
    rule_index = rule_line.split('[')[1].split(']')[0]
    return rule_index

class GeneralRules(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)
        self.parent = parent
        global scrollable_general_rules
        scrollable_general_rules = ctk.CTkScrollableFrame(self)
        scrollable_general_rules.pack(fill='both', expand=True)
        scrollable_general_rules.columnconfigure(0, weight=1)
        scrollable_general_rules.columnconfigure(1, weight=1)

        self.show_general_rules()
    
    def show_general_rules(self):
        for widget in scrollable_general_rules.grid_slaves():
            widget.grid_remove()

        label = ctk.CTkLabel(scrollable_general_rules, text="Rules Applied to All Connected Devices")
        label.grid(row = 0, column = 0, sticky = N, pady = 20, padx = 10, columnspan = 2)
        general_rules = get_firewall_rules()
        try:
            rules_without_index = [ {k: v for k, v in attributes.items() if (k != 'rule')} for attributes in general_rules]
            for i, rule in enumerate(rules_without_index): 
                rule_str = "\n".join([f"{key}: {value}" for key, value in rule.items()])
                rule_label = ctk.CTkLabel(scrollable_general_rules, text=rule_str, width=350)
                rule_label.grid(row=1+i, column=0, sticky = "E", pady=15, padx=10)
            for i, rule in enumerate(general_rules):
                button = ctk.CTkButton(scrollable_general_rules, text="edit rule", command = lambda rule = rule : edit_rules_modal(self, rule))
                button.grid(row=1+i, column=1, sticky = "W", pady=5, padx=10)
        except:
            print("first time loading")
        self.after(7000, self.show_general_rules)
        

    def create_menubar(self, parent):
        menubar = Menu(parent, bd=3, relief=RAISED)

        devicemenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Devices", menu=devicemenu)
        devicemenu.add_command(label="Connected devices", command=lambda: parent.show_frame(parent.HomePage))
        devicemenu.add_command(label="Managed devices", command=lambda: parent.show_frame(parent.ManagedDevices))

        setttingsmenu = Menu(menubar, tearoff=0, relief=RAISED)
        menubar.add_cascade(label="Settings", menu=setttingsmenu)
        setttingsmenu.add_command(label="New", command=lambda: parent.show_frame(parent.Settings))
        setttingsmenu.add_command(label="Usual rules", command=lambda: parent.show_frame(parent.GeneralRules)) 

        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About")
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar
    
    
if __name__ == "__main__":
    with app.app_context():
        App().mainloop()
        

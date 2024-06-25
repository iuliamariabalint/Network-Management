import tkinter as tk
from tkinter import *
from tkinter import messagebox
import customtkinter as ctk
from flask import Flask
from database.db_creation import db, user, settings
import atexit, os
from logic.authentication import login, signup
from logic.router import save_router_data, send_command
from logic.devices import get_active_clients, add_device, delete_device, edit_device
from logic.firewall import get_firewall_rules, edit_rule, delete_rule


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/balin/Desktop/SQLite_DB/net-management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("green")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SafeGuardKids")
        self.geometry("750x550")
        self.resizable(True, True)
    
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
        self.UsualRules = UsualRules
        self.About = About

        for F in {LoginPage, SignupPage, RouterDataPage, HomePage, ManagedDevices, Settings, DeviceSettings, GeneralRules, UsualRules, About}:
            frame = F(self, container)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky = "nsew")    
           
        self.show_frame(LoginPage)
        atexit.register(self.delete_json_file)
        
    def show_frame(self, cont):
        frame = self.frames[cont]
        menubar = frame.create_menubar(self)
        self.configure(menu=menubar)
        frame.tkraise()                       
    
    def delete_json_file(self):
        file_path = "router_data.json"
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
        label.pack(pady=20)

        username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        username_entry.pack(pady=5)

        password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        password_entry.pack(pady=12)

        login_button = ctk.CTkButton(self, text="Login", command=lambda: login(self, parent, username_entry, password_entry))
        login_button.pack(pady=12)

        create_account_label = ctk.CTkLabel(self, text="Create an account:")
        create_account_label.pack(pady=8)

        signup_button = ctk.CTkButton(self, text="Sign up", cursor='hand2', command=lambda: parent.show_frame(parent.SignupPage))
        signup_button.pack(pady=1)

        
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
        label.pack(pady=20, padx=0)

        username_entry = ctk.CTkEntry(self, placeholder_text = "Username")
        username_entry.pack(pady = 5, padx = 10)

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

    
    def create_menubar(self, parent):
        pass

#---------------------------------------- ROUTER-DATA-PAGE / CONTAINER ------------------------------------------------------------------------
import json
from PIL import Image
class RouterDataPage(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)

        info = ctk.CTkLabel(self, text = "Please enter the router data")
        info.pack(pady = 20, padx = 10)

        user_entry = ctk.CTkEntry(self, placeholder_text = "Router admin")
        user_entry.pack(pady = 5, padx = 10)

        password_entry = ctk.CTkEntry(self, placeholder_text = "Router password", show="*")
        password_entry.pack(pady = 12, padx = 10)

        image = ctk.CTkImage(Image.open("assets/arrow.png"))
        button = ctk.CTkButton(self, text = "Connect", image = image, command = lambda: save_router_data(parent, user_entry, password_entry), compound="left")
        button.pack(pady = 12, padx = 10)
         
    def create_menubar(self, parent):
        pass

#---------------------------------------- HOME PAGE FRAME / CONTAINER ------------------------------------------------------------------------
import paramiko
from database.db_creation import device
import tkinter.font as tkFont

class HomePage(ctk.CTkFrame):
    def __init__(self, parent, container):
        super().__init__(container)
        
        self.parent_window = parent
        self.show_active_clients()
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        label = ctk.CTkLabel(self, text="Home Page")
        label.grid(row = 0, column = 0, columnspan = 2, sticky = N, pady = 20, padx = 10)

    def show_active_clients(self):
        dhcp_leases = get_active_clients(self)
        processed_macs = set()
        try:
            for i, dhcp_lease in enumerate(dhcp_leases):
                mac_address = dhcp_lease["mac_address"]
                ip_address = dhcp_lease["ip_address"]
                hostname = dhcp_lease["hostname"]
                client_id = dhcp_lease["client_id"]

                try: 
                    if mac_address in processed_macs: 
                        continue
                except:
                    return None

                processed_macs.add(mac_address)

                client_info = (f"MAC Address:  {mac_address}\n"
                               f"IP Address:       {ip_address}\n"
                               f"Hostname:        {hostname}\n"
                               f"Client ID:           {client_id}")
                label = ctk.CTkLabel(self, text=client_info, justify=LEFT)
                label.grid(row=i+1, column=0, sticky = E, pady=30, padx=10)

                existing_device = device.query.filter_by(MAC_address = mac_address).first()
                if existing_device:
                    manage_label = ctk.CTkLabel(self, text = "Managed", text_color = "#5AD194", width=140)
                    manage_label.grid(row=i+1, column=1, sticky=W, pady=45, padx=10)
                else:
                    button = ctk.CTkButton(self, text="Manage", command = lambda info = dhcp_lease: self.settings_modal(info))
                    button.grid(row=i+1, column=1, sticky = W, pady=45, padx=10)
        except:
            print("firt time running")
        self.after(5000, self.show_active_clients)

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

        add_button = ctk.CTkButton(modal, text="Add", command = lambda: add_device(modal, device_types, devicename_entry, mac_addr, device_type_dropdown))
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
        help_menu.add_command(label="About", command=lambda: parent.show_frame(parent.About))
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
            device_data = (f"{dev.device_name}\n"
                           f"MAC address: {dev.MAC_address}\n"
                           f"Device type:    {dev.device_type}")

            label = ctk.CTkLabel(self, text=device_data, anchor=W, justify=LEFT)
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
        help_menu.add_command(label="About", command=lambda: parent.show_frame(parent.About))
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit) 

        return menubar

#---------------------------------------------------DEVICE SETTINGS FRAME / CONTAINER --------------------------------------------------

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

        delete_button = ctk.CTkButton(scrollable_frame, fg_color="transparent", hover_color="#F24A3B", text="delete", command = lambda: delete(self.parent))
        delete_button.grid(row = 5, column = 0, pady = 5, columnspan = 2, sticky = "n")

        done_button = ctk.CTkButton(scrollable_frame, text="done", command = lambda: edit(self.parent))
        done_button.grid(row = 6, column = 0, padx=5, pady=5, columnspan = 2, sticky = "n")

        title2 = ctk.CTkLabel(scrollable_frame, text = "ACTIVE RULES")
        title2.grid(row = 7, column = 0, pady=15, columnspan = 2, sticky = "n")

        active_rules = get_firewall_rules(mac_address)
        print("active rules for this device are: ", active_rules)
    
        try:
            rules_without_index = [ {k: v for k, v in attributes.items() if k != 'rule'} for attributes in active_rules]
            for i, rule in enumerate(rules_without_index):
                rule_str = "\n".join([f"{key}: {value}" for key, value in rule.items()])
                rule_label = ctk.CTkLabel(scrollable_frame, text=rule_str, width=300, anchor=W, justify=LEFT)
                rule_label.grid(row=8+i, column=0, sticky = E, pady=15, padx=10)
            for i, rule in enumerate(active_rules):
                button = ctk.CTkButton(scrollable_frame, text="edit rule", command = lambda rule = rule : edit_rules_modal(self, rule, mac_address))
                button.grid(row=8+i, column=1, sticky = W, pady=5, padx=10)
        except:
            print("first time loading")

        def delete(parent):
            delete_device(mac_address, self.parent)
            parent.show_frame(ManagedDevices)
    
        def edit(parent):
            edit_device(self.parent, devicename_entry, mac_address, device_type_dropdown)
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
        help_menu.add_command(label="About", command=lambda: parent.show_frame(parent.About))
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

        selected_days = []
        weekdays_listbox = None
        websites_entry = None
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
        
        edit_button = ctk.CTkButton(scrollable_frame, text="edit", command = lambda : edit_rule(modal, self, name_entry, existing_setting, iddevice_setting, stop_entry, start_entry, 
                 rule_name, rule_number, start, stop, days, weekdays_listbox, selected_days, ip_value, websites_entry))
        edit_button.grid(pady = 10)

        delete_button = ctk.CTkButton(scrollable_frame, fg_color="transparent", hover_color="#F24A3B", text="delete", command = lambda : delete_rule(modal, self, rule_number, existing_setting))
        delete_button.grid(pady = 5)

        start_index = rule["name"].index('-') + 1
        end_index = rule["name"].index('@')
        iddevice_setting = rule["name"][start_index:end_index]
        existing_setting = device_setting.query.filter_by(iddevice_setting = iddevice_setting).first()



#---------------------------------------------------SETTINGS FRAME / CONTAINER --------------------------------------------------
from functools import partial
from database.db_creation import settings
from tkinter import ttk
from CTkListbox import CTkListbox
from database.db_creation import device_setting
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
            button = ctk.CTkButton(self, text = name, command = button_command, width=250)
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
                rule_name = f"SafeGuardKids-{id_devicesetting}@{name}"

                command = f"""uci add firewall rule
                            uci set firewall.@rule[-1].name='{rule_name}'
                            uci set firewall.@rule[-1].src={src}
                            uci set firewall.@rule[-1].src_mac={mac}
                            uci set firewall.@rule[-1].dest={dest}
                            uci set firewall.@rule[-1].start_time={start}
                            uci set firewall.@rule[-1].stop_time={stop}
                            uci set firewall.@rule[-1].weekdays="{short_days}"
                            uci set firewall.@rule[-1].target={target}
                            uci commit firewall
                            service firewall restart"""
                send_command(client, command)
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
                rule_name = f"SafeGuardKids-{id_devicesetting}@{name}"
                addresses_list = []
                for website in websites:
                    ip_command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"
                    ip_address = send_command(client, ip_command)
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

                send_command(client, firewall_command)
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
                rule_name_websites = f"SafeGuardKids-{id_devicesetting1}@{name}"
                rule_name_block = f"SafeGuardKids-{id_devicesetting2}@Block all access"
                addresses_list = []
                for website in websites:
                    ip_command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"
                    ip_address = send_command(client, ip_command)
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
                send_command(client, firewall_command)
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
        help_menu.add_command(label="About", command=lambda: parent.show_frame(parent.About))
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar
    
#---------------------------------------------------GENERAL RULES FRAME / CONTAINER --------------------------------------------------
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
        print("general rules", general_rules)
        try:
            rules_without_index = [ {k: v for k, v in attributes.items() if (k != 'rule')} for attributes in general_rules]
            for i, rule in enumerate(rules_without_index): 
                rule_str = "\n".join([f"{key}: {value}" for key, value in rule.items()])
                rule_label = ctk.CTkLabel(scrollable_general_rules, text=rule_str, width=300, anchor=W, justify=LEFT)
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
        help_menu.add_command(label="About", command=lambda: parent.show_frame(parent.About))
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar
    
#---------------------------------------------------USUAL RULES FRAME / CONTAINER --------------------------------------------------   
class UsualRules(ctk.CTkFrame):

    def __init__(self, parent, container):
        super().__init__(container)
        label = ctk.CTkLabel(self, text="Saved Templates")
        label.grid(row = 0, column = 0, sticky = N, pady = 20, padx = 10, columnspan = 2)

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
        help_menu.add_command(label="About", command=lambda: parent.show_frame(parent.About))
        help_menu.add_separator()
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar

#--------------------------------------------------- ABOUT FRAME / CONTAINER --------------------------------------------------   
class About(ctk.CTkFrame):
    
    def __init__(self, parent, container):
        super().__init__(container)
        global scrollable_about
        scrollable_about = ctk.CTkScrollableFrame(self)
        scrollable_about.pack(fill='both', expand=True)
        label = ctk.CTkLabel(scrollable_about, text="User guide")
        label.grid(row = 0, column = 0, sticky = N, pady = 20, padx = 10, columnspan = 2)
        guide_text= """
                        Authentication

                        Upon launching the application, the login page appears. If the user already has an account, 
                        they can enter their username in the top field and their password in the bottom field. 
                        After entering this information, they should press the "Login" button. If the entered data is incorrect, 
                        an error window will appear to alert the user. If the user does not have an account, 
                        they can press the "Sign up" button to be redirected to the account creation page. 
                        Here, they are required to enter a username and password for the new account. 
                        The username must be unique in the database, so if the chosen name is already in use, 
                        an error window will appear. If the account is successfully created, a confirmation message will appear. 
                        The user can then return to the login page by pressing the "Login" button to authenticate. 
                        Once successfully authenticated, the application will proceed to the next page.

                        Router Connection

                        The next page is where the user enters the login credentials for the router they wish to manage, 
                        as shown in figure ?. The user must enter the router's account details, namely the username and password. 
                        Next, they press the "Connect" button to initiate the connection to the router. 
                        If the connection fails due to incorrect account details or router unavailability, 
                        the user will be notified through an error window. If the connection is successfully established, 
                        the application will move to the main page.

                        Device Management

                        The page displaying devices connected to the router is considered the application's main page 
                        because it is where interaction with network devices begins. This page displays information about 
                        each connected device, such as MAC address, IP address, hostname, and client identifier. 
                        To manage a device, the user must click the "Manage" button associated with it. A window will appear, 
                        where preliminary settings such as changing the hostname for easier identification 
                        (e.g., from "Ubuntu" to "Child PC 1") and specifying the type of device (computer, mobile, laptop, etc.) 
                        must be configured. After making these settings, click the "Add" button to add the device under management. 
                        The "Manage" button associated with that device will be replaced with a label indicating 
                        "managed" to identify which devices among those connected are already managed. At the top of 
                        the page is the application menu, divided into three sections: "Devices," "Settings," and "Help." The "Devices" 
                        section allows the user to access the managed devices page through the "Managed Devices" button. 
                        The "Settings" section offers three options: creating a new rule with the "New" button, viewing rules applied to 
                        all devices with the "General Rules" button, and viewing existing rule templates with the "Usual Rules" 
                        button. The "Help" section contains the "About" option, where the application guide is located, 
                        and the option to exit the application with the "Exit" button. This menu is accessible from all pages with minor 
                        modifications depending on the user's current page.

                        If the user wants to view managed devices, they can click on the "Managed Devices" button. 
                        This page displays all devices managed within the application. The user has the option to 
                        edit a device by pressing the "Edit" button associated with it. In this case,
                        the page will switch to the device settings page, where desired modifications can be made. 
                        The user can edit the hostname or device type if entered incorrectly during device management. 
                        To save the edits, click the "Done" button. Additionally, the user can completely delete 
                        the device from management, for example, if it is no longer in use.

                        On this page, active rules applied to that specific device can also be viewed, but only those 
                        specific to it. Each active rule has an associated edit button. Clicking it triggers a window 
                        where the rule can be edited or deleted. To add a new setting, go to the "Settings" menu and 
                        click "New". The page will switch to the settings page, where available setting types and a brief 
                        description of each are displayed. Each setting has a button that, when pressed, opens a window where 
                        necessary data must be entered. For example, to add a setting for blocking internet access 
                        except for specific websites ("Block all access except for some websites"), the following information is 
                        required: rule name (a default name exists but can be edited), allowed websites (separated by commas, 
                        e.g., "cv.upt.ro,upt.ro"), selection of a specific device if the setting applies only to that device 
                        (if nothing is selected, the setting will apply to all devices connected to the router), start time for 
                        applying the rule, and end time if applying the setting for a specific period. To set the rule, click the 
                        "Submit" button. After this, the window will close, and another rule can be added if desired. 
                        The added setting will appear under "Managed Devices" for the specific device for which the rule was created,
                        or under "General Rules" if applied to all devices. The same process applies to other rules. 
                        All fields contain information on how they should be completed or helpful information. After 
                        filling out these fields, click "Submit" to apply the rule.

                        To view existing rules on all devices attached to the network, go to the "Settings" menu and click 
                        "General Rules". The page will switch to the general settings page, shown in figure x, where active 
                        rules can be viewed. Each rule has an associated "Edit" button, which, when clicked, opens a window 
                        where those rules can be edited or deleted.

                        To view templates created based on applied rules, go to the "Settings" menu and click "Usual Rules". 
                        The page will switch to the usual rules page, shown in figure x, where existing templates can be viewed. 
                        Each template has an associated "Apply on Device" button, which, when clicked, opens a window where the 
                        device on which the template is to be applied must be selected. After selecting the device, 
                        click "Apply" to activate the setting.

                    """
        guide_label = ctk.CTkLabel(scrollable_about, text=guide_text, anchor="center", justify=LEFT)
        guide_label.grid(sticky=NSEW)

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
        help_menu.add_command(label="Exit", command=parent.quit)

        return menubar
    
    
if __name__ == "__main__":
    with app.app_context():
        App().mainloop()
        

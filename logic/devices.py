import customtkinter as ctk
import tkinter as tk
from tkinter import *
from tkinter import messagebox
import json
from database.db_creation import db, device
from logic.router import execute_command

def get_active_clients(self):
    try:
        command = "cat /tmp/dhcp.leases"
        active_clients = execute_command(command)
        dhcp_leases = []
        processed_macs = set()
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
        return dhcp_leases
    except AttributeError:
         print("first time")

def add_device(modal, device_types, devicename, mac_addr, devicetype):
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

def delete_device(mac_addr, parent):
    existing_device = device.query.filter_by(MAC_address = mac_addr).first()
    if existing_device:
        db.session.delete(existing_device)
        db.session.commit()
    
def edit_device(parent, devicename, mac_addr, devicetype):
    device_name = devicename.get()
    device_type = devicetype.get()
    existing_device = device.query.filter_by(MAC_address = mac_addr).first()
    if existing_device:
        existing_device.device_name = device_name
        existing_device.device_type = device_type
        db.session.commit()
import json
import paramiko
from tkinter import messagebox

def save_router_data(parent, user_entry, password_entry):
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

def execute_command(command):
    try:
            with open('router_data.json') as data_file:
                router_data = json.load(data_file)

            host = router_data['ip_address']
            username = router_data['router_user']
            password = router_data['router_password']
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, username=username, password=password)

            stdin, stdout, stderr = client.exec_command(command)
            output = stdout.read().decode()
            client.close()
            return output
    except FileNotFoundError:
        print("The JSON file wasn't found")

def ssh_connection():
    try:
            with open('router_data.json') as data_file:
                router_data = json.load(data_file)

            host = router_data['ip_address']
            username = router_data['router_user']
            password = router_data['router_password']
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, username=username, password=password)
            return client
    except FileNotFoundError:
        print("The JSON file wasn't found")

def send_command(client, command):
        stdin, stdout, stderr = client.exec_command(command)
        return stdout.read().decode()
import json
import paramiko
import bcrypt
import customtkinter

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("dark-blue")

def main_page():
    root = customtkinter.CTk()
    root.title("Active clients")
    
    # Get the screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Set the window size to the screen resolution
    root.geometry(f"{screen_width}x{screen_height}")

    data = open('router_data.json')
    router_data = json.load(data)

    command = "cat /tmp/dhcp.leases"

    host = router_data['ip_address']
    username = router_data['router_user']
    password = router_data['router_password']

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
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
    
    with open('active_clients.json') as f:
        clients = json.load(f)
    
    for lease in dhcp_leases:
        client_info = f"MAC Address: {lease['mac_address']}\nIP Address: {lease['ip_address']}\nHostname: {lease['hostname']}\nClient ID: {lease['client_id']}"
        label = customtkinter.CTkLabel(root, text=client_info)
        label.pack(pady = 50, padx = 10)

    root.mainloop()

if __name__ == "__main__":
    main_page()



from tkinter import messagebox
import json
from .router import execute_command, ssh_connection, send_command
import re
from collections import defaultdict
from database.db_creation import db

def get_firewall_rules(mac=None):
    try:
        command = "uci show firewall"
        output = execute_command(command)
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
    except AttributeError:
        print("first time loading")

def edit_rule(modal, self, name_entry, existing_setting, iddevice_setting, stop_entry, start_entry, 
                 rule_name, rule_number, start, stop, days=None, weekdays_listbox=None, selected_days=None, ip_value=None, websites_entry=None):
    name = name_entry.get()
    if existing_setting:
        setting_value_ = existing_setting.setting_value
        new_name = f"SafeNet-{iddevice_setting}@{name}"
    new_stop = stop_entry.get()
    new_start = start_entry.get()
    client = ssh_connection()
    if rule_name != new_name:
        change_name = f"uci set firewall.@rule[{rule_number}].name='{new_name}'"
        send_command(client, change_name)
        setting_value_["rule name"] = new_name 
    if start:
        if start != new_start:
            if len(new_start) != 8:
                messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                return
            else:
                change_start = f"uci set firewall.@rule[{rule_number}].start_time='{new_start}'"
                send_command(client, change_start)
                existing_setting.start_time = new_start
    elif new_start:
        if len(new_start) != 8:
            messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
            return
        else:
            add_start = f"uci set firewall.@rule[{rule_number}].start_time='{new_start}'"
            send_command(client, add_start)
            existing_setting.start_time = new_start
    if stop:
        if stop != new_stop:
            if len(new_stop) != 8:
                messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
                return
            else:
                change_stop = f"uci set firewall.@rule[{rule_number}].stop_time='{new_stop}'"
                send_command(client, change_stop)
                existing_setting.end_time = new_stop
    elif new_stop:
        if len(new_stop) != 8:
            messagebox.showerror("Error", "Please enter the correct time format hh:mm:ss")
            return
        else:
            add_stop = f"uci set firewall.@rule[{rule_number}].stop_time='{new_stop}'"
            send_command(client, add_stop)
            existing_setting.end_time = new_stop  
    if days:
        new_weekdays = weekdays_listbox.get()
        weekdays_str = " ".join(new_weekdays)
        if selected_days != new_weekdays:
            change_weekdays = f"uci set firewall.@rule[{rule_number}].weekdays='{weekdays_str}'"
            send_command(client, change_weekdays)
            setting_value_["affected days"] = weekdays_str
    if ip_value:
        new_websites = websites_entry.get().strip().split(",")
        new_websites = [ip.strip() for ip in new_websites]
        ip_list = ip_value.split(" ")
        print(ip_list)
        addresses_list = []
        for website in new_websites:
            ip_command = f"nslookup {website} | awk '/^Address: / {{ print $2 }}'"
            ip_address = send_command(client, ip_command)
            first_ip_address = ip_address.split('\n')[0].strip()
            addresses_list.append(first_ip_address)
            addresses = " ".join(addresses_list)
        if ip_list != addresses_list:
            change_websites = f"uci set firewall.@rule[{rule_number}].dest_ip='{addresses}'\n"
            send_command(client, change_websites)
            setting_value_["websites"] = addresses
        else:
            print("same websites as before")
    final_command = """uci commit firewall
                        service firewall restart"""
    send_command(client, final_command)
    client.close()
    print(setting_value_)
    existing_setting.setting_value = setting_value_
    db.session.commit()
    print("Changes committed to the database")
    modal.destroy()
    calling_class = self.__class__.__name__
    if calling_class == "DeviceSettings":
        self.show_device_settings()
    if calling_class == "GeneralRules":
        self.show_general_rules()

def delete_rule(modal, self, rule_number, existing_setting):
    command = f"""uci delete firewall.@rule[{rule_number}]
                uci commit firewall
                service firewall restart"""
    execute_command(command)
    if existing_setting:
        db.session.delete(existing_setting)
        db.session.commit()
    modal.destroy()    
    calling_class = self.__class__.__name__
    if calling_class == "DeviceSettings":
        self.show_device_settings()
    if calling_class == "GeneralRules":
        self.show_general_rules()

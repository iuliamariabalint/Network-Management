from tkinter import messagebox
import bcrypt
from database import db, user

def login(self, parent, username_entry, password_entry):
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

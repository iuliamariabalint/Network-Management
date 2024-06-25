from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped
from sqlalchemy import Integer, String, Column, VARCHAR, Enum, FLOAT, JSON, TIMESTAMP
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/balin/Desktop/SQLite_DB/net-management.db'
app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = 'False'
db = SQLAlchemy(app)

user_has_devices = db.Table( 'user_has_devices',
    db.Column('iduser', db.Integer, db.ForeignKey('user.iduser'), primary_key=True),
    db.Column('iddevice', db.Integer, db.ForeignKey('device.iddevice'), primary_key=True)
 )

class user(db.Model):
    __tablename__ = 'user'

    iduser = db.Column(db.Integer, primary_key = True, autoincrement = True)
    username = db.Column(db.VARCHAR(45), nullable = False, unique = True)
    password = db.Column(db.VARCHAR(64), nullable = False)
    account_type = db.Column(db.Enum('admin', 'standard'))
    devices = relationship('device', secondary = user_has_devices, back_populates='users')
    device_settings = relationship('device_setting', back_populates = 'user_')


class device(db.Model):
    __tablename__ = 'device'
    
    iddevice = db.Column(db.Integer, primary_key = True, autoincrement = True)
    device_name = db.Column(db.VARCHAR(45))
    MAC_address = db.Column(db.VARCHAR(17), nullable = False, unique = True)
    device_type = db.Column(db.Enum('Router', 'Extender', 'Mobile', 'Laptop', 'Computer', 'TV', 'Other'), nullable = False)
    users = relationship('user', secondary = user_has_devices, back_populates='devices')
    device_settings = relationship('device_setting', back_populates = 'device_', cascade="all, delete-orphan")


class device_setting(db.Model):
    __tablename__ = 'device_setting'

    iddevice_setting = db.Column(db.Integer, primary_key = True, autoincrement = True)
    iduser = db.Column(db.ForeignKey('user.iduser'), nullable = False)
    iddevice = db.Column(db.ForeignKey('device.iddevice'))
    idsetting = db.Column(db.ForeignKey('settings.idsetting'), nullable = False)
    setting_value = db.Column(db.JSON, nullable = False)
    setting_time = db.Column(db.DateTime, nullable = False)
    start_time = db.Column(db.VARCHAR(8))
    end_time = db.Column(db.VARCHAR(8))
    rule_name = db.Column(db.VARCHAR(50))
    setting = relationship('settings', back_populates = 'device_settings')
    user_ = relationship('user', back_populates = 'device_settings')
    device_ = relationship('device', back_populates = 'device_settings')

class settings(db.Model):
    __tablename__ = 'settings'

    idsetting = db.Column(db.Integer, primary_key = True, autoincrement = True)
    setting_name = db.Column(db.VARCHAR(45), nullable = False)
    description = db.Column(db.VARCHAR(100))
    device_settings = relationship('device_setting', back_populates= 'setting')

class templates(db.Model):
    __tablename__ = 'templates'

    idtemplate = db.Column(db.Integer, primary_key = True, autoincrement = True)
    setting_value = db.Column(db.JSON, nullable = False)
    rule_name = db.Column(db.VARCHAR(50), nullable = False)
    start_time = db.Column(db.VARCHAR(8))
    end_time = db.Column(db.VARCHAR(8))
    
block_access = settings(setting_name = 'Manage Access to Wi-fi' , description ='Manage which devices can access the network via Wi-fi')
time_restriction = settings(setting_name = 'Network Usage Scheduler' , description = 'Definition of specific time periods during which network access is permitted or restricted for a device.')

with app.app_context():
    db.create_all()
    # db.session.add(block_access)
    # db.session.add(time_restriction)

    # db.session.commit()

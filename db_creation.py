from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped
from sqlalchemy import Integer, String, Column, VARCHAR, Enum, FLOAT, JSON, TIMESTAMP
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/balin/Desktop/SQLite_DB/net-management.db'
app.config['SQLALCHEMY_TRACK_NOTIFICATIONS'] = 'False'
db = SQLAlchemy(app)

rigths = db.Table( 'rights',
    db.Column('iduser', db.Integer, db.ForeignKey('user.iduser'), primary_key=True),
    db.Column('iddevice', db.Integer, db.ForeignKey('device.iddevice'), primary_key=True)
 )

class user(db.Model):
    __tablename__ = 'user'

    iduser = db.Column(db.Integer, primary_key = True, autoincrement = True)
    username = db.Column(db.VARCHAR(45), nullable = False, unique = True)
    password = db.Column(db.VARCHAR(64), nullable = False)
    account_type = db.Column(db.Enum('admin', 'standard'))
    devices = relationship('device', secondary = rigths, back_populates='users')
    device_settings = relationship('device_setting', back_populates = 'user_')


class device(db.Model):
    __tablename__ = 'device'
    
    iddevice = db.Column(db.Integer, primary_key = True, autoincrement = True)
    device_name = db.Column(db.VARCHAR(45))
    MAC_address = db.Column(db.VARCHAR(17), nullable = False, unique = True)
    device_type = db.Column(db.Enum('Router', 'Extender', 'Mobile', 'Laptop', 'Computer', 'TV', 'Other'), nullable = False)
    users = relationship('user', secondary = rigths, back_populates='devices')
    device_settings = relationship('device_setting', back_populates = 'device_', cascade="all, delete-orphan")
    outgoing_connections = db.relationship('connection', foreign_keys='connection.iddevice_source', back_populates='source_device')
    incoming_connections = db.relationship('connection', foreign_keys='connection.iddevice_destination', back_populates='destination_device')

class connection(db.Model):
    __tablename__ = 'connection'

    iddevice_source = db.Column(db.Integer, db.ForeignKey('device.iddevice'), primary_key = True)
    iddevice_destination = db.Column(db.ForeignKey('device.iddevice'), primary_key = True)
    connection_type = db.Column(db.Enum('LAN', 'WLAN'), nullable = False) #WAN nu e necesar
    speed = db.Column(db.FLOAT)
    bandwidth = db.Column(db.Enum('2.4GHz', '5GHz')) #banda de frecventa e mandatory doar daca e conexiune wireless
    source_device = db.relationship('device', foreign_keys=[iddevice_source], back_populates='outgoing_connections')
    destination_device = db.relationship('device', foreign_keys=[iddevice_destination], back_populates='incoming_connections')

class device_setting(db.Model):
    __tablename__ = 'device_setting'

    iddevice_setting = db.Column(db.Integer, primary_key = True, autoincrement = True)
    iduser = db.Column(db.ForeignKey('user.iduser'), nullable = False)
    iddevice = db.Column(db.ForeignKey('device.iddevice'))
    idsetting = db.Column(db.ForeignKey('settings.idsetting'), nullable = False)
    setting_value = db.Column(db.JSON)
    setting_time = db.Column(db.DateTime, nullable = False)
    start_time = db.Column(db.VARCHAR(8))
    end_time = db.Column(db.VARCHAR(8))
    start_date = db.Column(db.VARCHAR(10))
    end_date = db.Column(db.VARCHAR(10))
    rule_number = db.Column(db.Integer)
    setting = relationship('settings', back_populates = 'device_settings')
    user_ = relationship('user', back_populates = 'device_settings')
    device_ = relationship('device', back_populates = 'device_settings')

class settings(db.Model):
    __tablename__ = 'settings'

    idsetting = db.Column(db.Integer, primary_key = True, autoincrement = True)
    setting_name = db.Column(db.VARCHAR(45), nullable = False)
    description = db.Column(db.VARCHAR(100))
    device_settings = relationship('device_setting', back_populates= 'setting')


block_access = settings(setting_name = 'Manage Access to Wi-fi' , description ='Manage which devices can access the network via Wi-fi')
time_restriction = settings(setting_name = 'Network Usage Scheduler' , description = 'Definition of specific time periods during which network access is permitted or restricted for a device.')

with app.app_context():
    db.create_all()
    # db.session.add(block_access)
    # db.session.add(time_restriction)

    # db.session.commit()

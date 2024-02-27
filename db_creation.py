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
    device_settings = relationship('device_setting', back_populates = 'device_')
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
    iduser = db.Column(db.ForeignKey('user.iduser'))
    iddevice = db.Column(db.ForeignKey('device.iddevice'))
    idsetting = db.Column(db.ForeignKey('settings.idsetting'))
    setting_value = db.Column(db.JSON)
    setting_time = db.Column(db.DateTime, nullable = False)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    setting = relationship('settings', back_populates = 'device_settings')
    user_ = relationship('user', back_populates = 'device_settings')
    device_ = relationship('device', back_populates = 'device_settings')

class settings(db.Model):
    __tablename__ = 'settings'

    idsetting = db.Column(db.Integer, primary_key = True, autoincrement = True)
    setting_name = db.Column(db.VARCHAR(45), nullable = False)
    description = db.Column(db.VARCHAR(100))
    device_settings = relationship('device_setting', back_populates= 'setting')


john_doe = user(username='john_doe', password='password123', account_type='standard')
susana = user(username='susana50', password='password123', account_type='admin')
router = device(device_name='Router principal', MAC_address='00:11:22:33:44:55', device_type='Router')
laptop = device(device_name='laptop iulia', MAC_address='00:22:41:30:47:50', device_type='Laptop')
setare = device_setting(setting_time = datetime.now(), start_time = datetime(2024, 2, 13, 21, 00, 00))
blocare_acces = settings(setting_name = 'Blocare acces' , description = 'Blocarea accesului unui device in retea')
tv = device(device_name = 'TV sufragerie', MAC_address = '00:12:11:30:AF:50', device_type = 'TV')

with app.app_context():
    db.create_all()
    # db.session.add(john_doe)
    # db.session.add(susana)
    # db.session.add(router)
    # db.session.add(laptop)
    # db.session.add(tv)
    # db.session.add(setare)
    # db.session.add(blocare_acces)
    # susana = db.session.query(user).filter_by(username='susana50').first()
    # router_s = db.session.query(device).filter_by(iddevice=1).first()
    # susana.devices.append(router_s)
    # susana = db.session.query(user).filter_by(username='susana50').first()
    # laptop_s = db.session.query(device).filter_by(iddevice = 2).first()
    # susana.devices.append(laptop_s)
    # john_doe = db.session.query(user).filter_by(username = 'john_doe').first()
    # tv_j = db.session.query(device).filter_by(iddevice = 3).first()
    # john_doe.devices.append(tv_j)
    # setare1 = db.session.query(settings).filter_by(idsetting=1).first()
    # blocare_acces = db.session.query(device_setting).filter_by(iddevice_setting = 1).first()
    # setare1.device_settings.append(blocare_acces)
    # blocare_acces = db.session.query(device_setting).filter_by(iddevice_setting = 1).first()
    # susana = db.session.query(user).filter_by(iduser = 2).first()
    # susana.device_settings.append(blocare_acces)
    # blocare_acces = db.session.query(device_setting).filter_by(iddevice_setting = 1).first()
    # router_s = db.session.query(device).filter_by(iddevice=1).first()
    # router_s.device_settings.append(blocare_acces)
    # router_s = db.session.query(device).filter_by(iddevice = 1).first()
    # laptop_s = db.session.query(device).filter_by(iddevice = 2).first()
    # connection1 = connection(source_device = router_s, destination_device = laptop_s, connection_type = 'LAN', speed = 512.65)
    # db.session.add(connection1)

    db.session.commit()


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Message
from cryptography.fernet import Fernet
import os
from datetime import datetime

engine = create_engine('postgresql://messages:greenflowerplus@localhost/messages')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

#Load the key for symmetric encryption
file_uri = "/home/messages/messages/key.txt"
if os.path.exists(file_uri):
    key_file = open(file_uri, "rb")
    key = key_file.read()
    f = Fernet(key)
else:
    print("Error: 'key.txt' didn't found")
    exit()


# Create users
user1 = User(name=f.encrypt("First User".encode()),
             username=f.encrypt("user1".encode()),
             security_question=f.encrypt("This is the pass phrase of user1".encode()))
user1.hash_password("1234")
user1.hash_passw_phrase_answer("user1")
session.add(user1)
session.commit()

user2 = User(name=f.encrypt("Second User".encode()),
             username=f.encrypt("user2".encode()),
             security_question=f.encrypt("This is the pass phrase of user2".encode()))
user2.hash_password("2345")
user2.hash_passw_phrase_answer("user2")
session.add(user2)
session.commit()


# Create messages
sender_user = session.query(User).filter_by(id=user1.id).one()
recipient_user = session.query(User).filter_by(id=user2.id).one()

message1 = Message(sender_id=sender_user.id,
                   sender_name=sender_user.name,
                   sender_username=sender_user.username,
                   sender_ip='192.168.0.1',
                   recipient_id=recipient_user.id,
                   title=f.encrypt("First Message from user1".encode()),
                   content=f.encrypt("This is the content of the first message from user1 to user2.".encode()),
                   creation_time=datetime.utcnow())
session.add(message1)
session.commit()

message2 = Message(sender_id=sender_user.id,
                   sender_name=sender_user.name,
                   sender_username=sender_user.username,
                   sender_ip='192.168.0.1',
                   recipient_id=recipient_user.id,
                   title=f.encrypt("Second Message from user1".encode()),
                   content=f.encrypt("This is the content of the second message from user1 to user2.".encode()),
                   creation_time=datetime.utcnow())
session.add(message2)
session.commit()

message3 = Message(sender_id=sender_user.id,
                   sender_name=sender_user.name,
                   sender_username=sender_user.username,
                   sender_ip='192.168.0.1',
                   recipient_id=recipient_user.id,
                   title=f.encrypt("Third Message from user1".encode()),
                   content=f.encrypt("This is the content of the third message from user1 to user2.".encode()),
                  creation_time=datetime.utcnow())
session.add(message3)
session.commit()


sender_user = session.query(User).filter_by(id=user2.id).one()
recipient_user = session.query(User).filter_by(id=user1.id).one()

message4 = Message(sender_id=sender_user.id,
                   sender_name=sender_user.name,
                   sender_username=sender_user.username,
                   sender_ip='192.168.0.1',
                   recipient_id=recipient_user.id,
                   title=f.encrypt("First Message from user2".encode()),
                   content=f.encrypt("This is the content of the first message from user2 to user1.".encode()),
                   creation_time=datetime.utcnow())
session.add(message4)
session.commit()

message5 = Message(sender_id=sender_user.id,
                   sender_name=sender_user.name,
                   sender_username=sender_user.username,
                   sender_ip='192.168.0.1',
                   recipient_id=recipient_user.id,
                   title=f.encrypt("Second Message from user2".encode()),
                   content=f.encrypt("This is the content of the second message from user2 to user1.".encode()),
                   creation_time=datetime.utcnow())
session.add(message5)
session.commit()


print("added messages and users!")

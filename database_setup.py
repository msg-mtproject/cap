#Configuration
from sqlalchemy import (Column,
                        ForeignKey,
                        Integer,
                        String,
                        LargeBinary,
                        TIMESTAMP,
                        create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from passlib.apps import custom_app_context as pwd_context
from cryptography.fernet import Fernet
import os

Base = declarative_base()

#Classes
class User(Base):
    #Table
    __tablename__ = 'user'
    #Mapper
    id = Column(Integer, primary_key=True)
    name = Column(LargeBinary(300))
    username = Column(LargeBinary(200))
    password_hash = Column(String(120))
    security_question = Column(LargeBinary(300))
    security_question_answer_hash = Column(String(120))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def hash_passw_phrase_answer(self, security_question_answer):
        self.security_question_answer_hash = pwd_context.encrypt(security_question_answer)

    def verify_passw_phrase_answer(self, security_question_answer):
        return pwd_context.verify(security_question_answer, self.security_question_answer_hash)

    @property
    def serialize(self):
        #Return object data in easily serializeable format
        return {
            'id'                            : self.id,
            'name'                          : self.name,
            'username'                      : self.username,
            'password_hash'                 : self.password_hash,
            'security_question'             : self.security_question,
            'security_question_answer_hash' : self.security_question_answer_hash
        }


class Message(Base):
    __tablename__ = 'message'

    id = Column(Integer, primary_key=True)
    sender_id =  Column(Integer)
    sender_name = Column(LargeBinary(300))
    sender_username = Column(LargeBinary(200))
    sender_ip = Column(String(50))
    recipient_id = Column(Integer, ForeignKey('user.id'))
    title = Column(LargeBinary(300))
    content = Column(LargeBinary(2000))
    creation_time = Column(TIMESTAMP)
    user = relationship(User)

    @property
    def serialize(self):
        #Return object data in easily serializeable format
        return {
            'id'                : self.id,
            'sender_id'         : self.sender_id,
            'sender_name'       : self.sender_name,
            'sender_username'   : self.sender_username,
            'sender_ip'         : self.sender_ip,
            'recipient_id'      : self.recipient_id,
            'title'             : self.title,
            'content'           : self.content,
            'creation_time'     : self.creation_time
        }


class MessageLog(Base):
    __tablename__ = 'message_log'

    id = Column(Integer, primary_key=True)
    sender_id =  Column(Integer)
    sender_name = Column(LargeBinary(300))
    sender_username = Column(LargeBinary(200))
    sender_ip = Column(String(50))
    recipient_id = Column(Integer, ForeignKey('user.id'))
    title = Column(LargeBinary(300))
    content = Column(LargeBinary(2000))
    recipient_name = Column(LargeBinary(300))
    recipient_username = Column(LargeBinary(200))
    recipient_ip = Column(String(50))
    creation_time = Column(TIMESTAMP)
    deletion_time = Column(TIMESTAMP)
    user = relationship(User)

    @property
    def serialize(self):
        #Return object data in easily serializeable format
        return {
            'id'                    : self.id,
            'sender_id'             : self.sender_id,
            'sender_name'           : self.sender_name,
            'sender_username'       : self.sender_username,
            'sender_ip'             : self.sender_ip,
            'recipient_id'          : self.recipient_id,
            'recipient_name'        : self.recipient_name,
            'recipient_username'    : self.recipient_username,
            'recipient_ip'          : self.recipient_ip,
            'title'                 : self.title,
            'content'               : self.content,
            'creation_time'         : self.creation_time,
            'deletion_time'         : self.deletion_time
        }

#Write the key for symmetric encryption
file_uri = "/home/messages/messages/key.txt"
if not os.path.exists(file_uri):
    key = Fernet.generate_key()
    key_file = open(file_uri, "wb")
    key_file.write(key)
    key_file.close()

#Database Configuration
#Create a new file database
engine = create_engine('postgresql://messages:greenflowerplus@localhost/messages')
#Go into the database and add the classes
Base.metadata.create_all(engine)
#End of Configuration

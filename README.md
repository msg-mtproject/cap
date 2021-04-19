# Messages Project

* For user registration, user should inform the `PIN` as `cap2021` for the capstone project running on web (see the link on the page course).

This project is an exercise, as part of **Cybersecurity Capstone Project**. It is a web application that provides message communication between the authenticated users.

It stores the information in a **PostgreSQL** database (<https://www.postgresql.org/>), using **SQLAlchemy** (<https://www.sqlalchemy.org/>) as the Object Relational Mapper.

It is written in **Python** (<https://www.python.org/>) and also uses **Flask** (<http://flask.pocoo.org/>) framework to map the routes, to render the templates, to extract data from forms, and to control the session.

# Installation

* These instructions are for installing the app as a Python local server, so we are not going to enter into details about the Apache server and configuration.

* You need to create and installation folder and copy the **Python** files `database_setup.py`, `make_users_and_messages.py` and `project.py`, supplied with this project, to a directory at the **Ubuntu 18.04 Linux** or equivalent (<https://www.ubuntu.com/>), that will host the "server". Also copy the `static` and `template` folders to the same folder.

* You need to install and set up the **PostgreSQL**, the **Redis** server (<https://redis.io/>), and (if it would serve with) the **Apache HTTP Server** (<https://httpd.apache.org>). As we are going to run locally (logged in into the host, using the local web browser), we do not need to install the Apache.

* You would need to install and set up the **WSGI Flask** module for the **Apache** (<http://flask.pocoo.org/docs/1.0/deploying/mod_wsgi/>), if it were be a web server, but we don't need as a local server.

* Here are the cheat sheet of the commands. You should install all the libraries needed, according to the `import` statements at the beginning of `project.py`:

      sudo apt-get -qqy install make zip unzip postgresql  
      sudo apt-get -qqy install python3 python3-pip  
      sudo apt install redis-server

      sudo pip3 install --upgrade pip  
      sudo pip3 install flask packaging oauth2client redis passlib flask-httpauth  
      sudo pip3 install sqlalchemy flask-sqlalchemy psycopg2-binary bleach requests  
      sudo pip3 install cryptography  
      sudo pip install flask-talisman

* Setting up the **PostgreSQL**:

    Create a Linux user account named 'messages'.

    In the 'postgres' Linux account (log into 'postgres' first) we can create a new user(role) named 'messages':

      $ sudo su postgres

      postgres@<local>$ createuser --interactive

      superuser? no
      allowed create databases? yes
      allowed create more new roles? no

    In the 'messages' user account (log into the 'messages' Linux account), we can create a database:

      $createdb messages

    Still in the 'messages' account, log into Postgres:

      messages@<local>$ psql

    Add a password for the user (need to add for the postgresql to work):

      ALTER USER <user> PASSWORD 'newPassword';

    Adjust the program, at the `create_engine` function, to use the same password. Also verify the `UPLOAD_FOLDER` on the `app.config` of the `Flask` (inside the `project.py`).

    Log into your user account and investigate sockets:

      $ sudo ss -ltpn

    You should see the `Redis` and `Postgres` servers listening only locally. Please, confirm this information.

* Creating a database password file for `pg_dump` use:

    Create a `.pgpass` file with the content for the database:

      hostname:port:database:username:password

    The `port` is the port that PostgreSQL is serving, and `hostname` is "localhost".

* Setting up the webserver port:

  - at the final of `project.py`, there is a line where shows the `port=8080` inside the **Flask** `run` method. It is the server port. [For a web server, you should change to `port=80` (leave as 8080 because we are serving locally).] For more instructions, see the link <http://flask.pocoo.org/docs/0.12/quickstart/>  


* You need to create some files and directories. Log into 'messages', create a directory '/home/messages/messages' and inside it, create a file 'pin.txt'. Put some string with a few characters. This will be used as a 'pin' to allow a user to create an account.

* Go to the installation folder (where it is database_setup.py) and command to create the database:

        $ python3 database_setup


# Common usage

* For users registration, users need to inform the `PIN` as `cap2021` for the capstone project running on web.

* As a local server, after running the program with the `python3 project.py` command, it is possible to access the app by typing the <http://localhost:8000/> in your local browser (logged in into the host, where we have installed the software, you should open the browser and type the local address above).

* The `make_users_and_messages.py` can be used for testing, for populate the database with some users and messages. Go to the installation folder and command:

      $ python3 make_users_and_messages.py

  It will create two users ('user1':1234) and ('user2':2345) and some automatic messages between them.

* If it were a web server, the **Apache2** (with the `libapache2-mod-wsgi` module installed) it would load the **Python** modules as a **WSGI** application.

* Users can authenticate at the `Login` page. On the same page, there are links to register a new user and to reset the password.

* The user must be registered to use the app. On the `Registration` page, the user must inform the `name`, the `username`, and create a `password`.

* In the registration, it is possible to create a `security question` and its `answer` to use when is necessary to reset the password.

* The program measures the password strength (approximately), and guides the user in choosing best practices.

* On the `Inbox` page, the user can read and write messages to other users, but must be authenticated first. It is also possible to delete the messages, but the deleted messages will be logged (saved).

* Clicking on the `message title` will open the content of the message.

* The messages are saved in a **PostgreSQL** database, after been cryptographed using the **Fernet** implementation of symmetric key, which is built on top of `AES` in `CBC` mode with a 128-bit key for encryption, and using `PKCS7` padding (<https://cryptography.io/en/latest/fernet/>)
(https://github.com/pyca/cryptography/blob/master/src/cryptography/fernet.py).

* It is also possible for everyone (not authenticated) to obtain a `database dump` by a GET query to the `/dbdump` path, which will retrieve the database content in the standard PostgreSQL format (plain text). Please, see detailed instructions at (<https://www.postgresql.org/docs/9.3/app-pgdump.html>). It is possible to restore with `pg_restore` (<https://www.postgresql.org/docs/9.3/app-pgrestore.html>).

* The `UPLOAD_FOLDER` variable (inside the `project.py`) should be the absolute path directory of the dump file on the server.

* The app implements `rate limiting` (<https://en.wikipedia.org/wiki/Rate_limiting>).


**This app is for learning purposes.** :books:

# Credits

These are some useful links that were queried in this project:

https://www.digitalocean.com/community/tutorials/how-to-install-linux-apache-mysql-php-lamp-stack-on-ubuntu-14-04

https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-14-04

https://www.digitalocean.com/community/tutorials/how-to-secure-postgresql-on-an-ubuntu-vps

https://www.digitalocean.com/community/tutorials/7-security-measures-to-protect-your-servers

https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-redis-on-ubuntu-18-04

http://httpd.apache.org/docs/current/configuring.html

https://stackoverflow.com/questions/43380273/pg-dump-pg-restore-password-using-python-module-subprocess

https://www.postgresql.org/docs/9.3/app-pgdump.html

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src

https://stackoverflow.com/questions/2893954/how-to-pass-in-password-to-pg-dump


*Important Python instructions:*

http://flask.pocoo.org/docs/0.12/deploying/mod_wsgi

http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls

https://github.com/GoogleCloudPlatform/flask-talisman

https://docs.python.org/2.6/library/subprocess.html


Thank You!

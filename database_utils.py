import sqlite3
from encryption_utils import AESCipher, hashed


def connect():
    """
    establish connection to the database
    :return: connection and cursor objects to interact with the database
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    return conn, cursor


def disconnect(conn):
    """
    disconnects the active conection to the database
    :param conn: connection object to the database
    :return:
    """
    conn.commit()
    conn.close()


def create_db():
    """
    creates new database and add two tables namely users and passwords
    :return:
    """
    with open("database.db", 'w'):
        pass
    conn, cursor = connect()

    cursor.execute('''CREATE TABLE users(
                    username TEXT NOT NULL,
                    master_pwd BLOB NOT NULL
                    );
                    ''')

    cursor.execute('''
                    CREATE TABLE passwords(
                    app_name TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password BLOB NOT NULL
                    );
                    ''')
    disconnect(conn)


def add_passwd(plain_data, key):
    """
    encrypts the received entry and insert it to the database

    :param plain_data: list consisting app_name, username, password
    :param key: hashed value of master password
    :return:
    """
    conn, cursor = connect()
    enc_data = encrypt_all(plain_data, key)
    cursor.execute('''INSERT INTO passwords (app_name, username, password)
                    VALUES ("{}", "{}", "{}")
                    '''.format(*enc_data))
    disconnect(conn)


def del_passwd(match, key):
    """

    :param match: list consisting app_name, username, password; which user want to delete
    :param key: hashed value of master password
    :return:
    """
    conn, cursor = connect()
    hashed_match = get_hashed_match(match, key)
    appn, usern, _ = [i for i in hashed_match]
    cursor.execute(f"DELETE FROM passwords WHERE (app_name='{appn}' AND username='{usern}')")
    disconnect(conn)


def list_all():
    """
    fetch all entries from the database
    :return: list of encrypted entries from the database
    """
    conn, cursor = connect()
    cursor.execute("SELECT * FROM passwords")
    result = cursor.fetchall()
    disconnect(conn)
    return result


def get_hashed_match(match, key):
    """
    finds the corresponding encrypted entry from the database
    :param match: list consisting app_name, username, password
    :param key: hashed value of master password
    :return: stored corresponding encrypted entry
    """
    results = list_all()
    for enc_data in results:
        plain_data = decrypt_all(enc_data, key)
        if match == plain_data:
            return list(enc_data)


def get_passwd(i_app_name, key):
    """
    finds all the matches by the given app_name
    :param i_app_name: app_name from the user
    :param key: hashed value of master password
    :return: return all matches with the app_name
    """
    results = list_all()
    matches = []
    for enc_data in results:
        plain_data = decrypt_all(enc_data, key)
        if i_app_name == plain_data[0]:
            matches.append(plain_data)
    return matches


def add_user(username, master_pass):
    """
    insert the user profile and hashed master password into database
    :param username: username for the vault
    :param master_pass: master password for the vault
    :return:
    """
    conn, cursor = connect()
    master_pass = hashed(master_pass)
    cursor.execute(f'''INSERT INTO users (username, master_pwd)
                    VALUES ("{username}", "{master_pass}")
                    ''')
    disconnect(conn)


def get_stored_master(username):
    """
    finds stored corresponding hashed value for the user if exists
    :param username: username for the vault
    :return: stored corresponding hashed value if exists
    """
    conn, cursor = connect()

    cursor.execute(f'SELECT master_pwd FROM users WHERE username="{username}"')
    stored_master = cursor.fetchone()
    disconnect(conn)
    if stored_master is None:
        return None
    else:
        return stored_master[0]


def verify_user(i_username, i_master):
    """
    verofy the user using the username and master password
    :param i_username: input username
    :param i_master: input master password
    :return: True and hashed master password if verified
    """
    stored_master = get_stored_master(i_username)
    if stored_master is not None:
        return stored_master == i_master, stored_master
    else:
        return False, None


def chng_passwd(match, new_pass, key):
    """
    change the password for the entry
    :param match: the entry which user wants to delete
    :param new_pass: new password for the app
    :param key: hashed master password
    :return:
    """
    del_passwd(match, key)
    plain_data = [match[0], match[1], new_pass]
    add_passwd(plain_data, key)


def encrypt_all(plain_data, key):
    """
    encrypts the plain entry
    :param plain_data: list of app_name, username, password
    :param key: hashed master password
    :return: encrypted entry
    """
    cipher = AESCipher(key)
    enc_app_name = cipher.encrypt(plain_data[0])
    enc_username = cipher.encrypt(plain_data[1])
    enc_password = cipher.encrypt(plain_data[2])
    return [enc_app_name, enc_username, enc_password]


def decrypt_all(enc_data, key):
    """
    decrypts the encrypted entry stored in database
    :param enc_data: encrypted data from the database
    :param key: hashed master password
    :return: plain decrypted entry
    """
    cipher = AESCipher(key)
    app_name = cipher.decrypt(enc_data[0])
    username = cipher.decrypt(enc_data[1])
    password = cipher.decrypt(enc_data[2])
    return [app_name, username, password]

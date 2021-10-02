import os
import getpass
from database_utils import *
from consts import *


def register():
    """
    registers the user and creates the database
    :return:
    """
    username = input("Enter username for yourself: ")
    master_passwd = getpass.getpass("Enter master password: ")
    master_passwdr = getpass.getpass("Enter master password again: ")
    if master_passwd == master_passwdr:
        create_db()
        add_user(username, master_passwd)
        print(REGISTRATION_SUCCESS_TEXT)
    else:
        print(REGISTRATION_FAILED_TEXT)
        register()


def new_passwd(key):
    """
    adds the new entry to the vault
    :param key: key to encrypt the plain data
    :return:
    """
    app_name = input("Enter app name: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    plain_data = [app_name, username, password]
    add_passwd(plain_data, key)


def retrieve_passwd(key):
    """
    retrieves the password from vault
    :param key: key to decrypt the encrypted data
    :return: matches found in the database
    """
    i_app_name = input("Enter app name: ")
    matches = get_passwd(i_app_name, key)
    if len(matches) > 1:
        print("Looks like there are multiple credentials associated with this app")
        match = get_spec_passwd(matches)
        match = [match]
    else:
        match = matches
    print_formatted(match)
    return match[0]


def delete_passwd(key):
    """
    delete the entry from vault
    :param key:
    :return:
    """
    match = retrieve_passwd(key)
    choice = input("Do you want to delete the above entry? (y/n): ")
    if choice == 'n':
        pass
    else:
        authorised, key = authorise()
        if authorised:
            del_passwd(match, key)
            print(DELETED_TEXT)


def list_apps():
    """
    lists all the apps saved to the vault
    :return:
    """
    results = list_all()
    print(f"Total {len(results)} entries found...")
    fetched = []
    for enc_data in results:
        plain_data = decrypt_all(enc_data, key)
        plain_data[2] = '*' * len(plain_data[2])
        fetched.append(plain_data)
    print_formatted(fetched)


def quit_passmgr():
    """
    quits the vault
    :return:
    """
    pass


def authorise():
    """
    authorise the user by asking and verifying the credentials
    :return: True and hashed master password if exists
    """
    username = input('Enter your username: ')
    # master = input('Enter your master password: ')
    master = getpass.getpass('Enter your master password: ')
    master = hashed(master)
    exists, key = verify_user(username, master)
    return exists, key


def change_passwd(key):
    """
    change the password
    :param key:
    :return:
    """
    match = retrieve_passwd(key)
    choice = input("Do you want to change the above password? (y/n): ")
    if choice == 'n':
        pass
    else:
        new_pass = input("Enter new password: ")
        authorised, key = authorise()
        if authorised:
            chng_passwd(match, new_pass, key)
            print(CHANGED_TEXT)


def print_formatted(results):
    """
    print entries in stylized format
    :param results: required matches
    :return:
    """
    print("------------------------------------------------------------------------------------------------")
    print("|           APP NAME             |           USERNAME         |           PASSWORD             |")
    print("------------------------------------------------------------------------------------------------")
    if len(results) == 1:
        print(f"|   {results[0][0]:29s}| {results[0][1]:27s}| {results[0][2]:31s}|")
        print("------------------------------------------------------------------------------------------------")
    else:
        cnt = 1
        for result in results:
            print(f"| {cnt}. {result[0]:28s}| {result[1]:27s}| {result[2]:31s}|")
            print("------------------------------------------------------------------------------------------------")
            cnt += 1


def get_spec_passwd(matches):
    """
    finds specific match by asking the username for the specific app_name
    :param matches: matches found by the app_name
    :return: unique match found based on the username
    """
    username = input("Enter username for the app: ")
    for match in matches:
        if username == match[1]:
            return match


if __name__ == '__main__':
    print(SUPER_START_TEXT)
    if not os.path.isfile('database.db'):
        register()
    failed_try = 0
    authorised, key = authorise()
    while not authorised:
        print(VERIFICATION_FAILED_TEXT)
        failed_try += 1
        if failed_try > 3:
            authorised = False
            print("You've exceeded maximum try limits !")
            break
        else:
            authorised, key = authorise()
    if authorised:
        choice = input(MENU_TEXT)
        while choice != 'q':
            if choice == 'n':
                new_passwd(key)
            elif choice == 'r':
                retrieve_passwd(key)
            elif choice == 'd':
                delete_passwd(key)
            elif choice == 'c':
                change_passwd(key)
            elif choice == 'l':
                list_apps()
            else:
                print(WRONG_INPUT_TEXT)
            choice = input(MENU_TEXT)
        quit_passmgr()
    else:
        quit_passmgr()

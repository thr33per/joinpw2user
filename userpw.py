#!/usr/bin/env python3
from sys import argv

pwdump = []  # format= <username>:<uid>:<LM-hash>:<NTLM-hash>:<comment>:<homedir>
generic = []  # format= <username>:<hash>
nixdump = []  # format= <username>:<hash>:<uid>:<gid>:<GECOS>:<directory>:<shell>
hashcat = []  # format= <hash>:<password>

# NTLM appears to be 32 characters long
# LM appears to also be 32 characters long


def open_file(file):
    try:
        temp = open(file, 'r')
        temp_list = []
        for record in temp:
            if record != '\n':
                temp_list.append(record)
        temp.close()
        return temp_list
    except FileNotFoundError:
        print('Unable to locate {0}'.format(file))


def save_file(file, pw_list):
    try:
        temp = open(file, 'a')
        for record in pw_list:
            temp.write('{0}\n'.format(record))
        temp.close()
        print("Your file has been saved to disk.")
    except PermissionError:
        permission_denied = True
        while permission_denied:
            print("It is not permissible to save in this location.")
            try_again = input("Is there somewhere else that you would like to try?") or 'No'
            if try_again in ('n', 'N', 'No', 'no'):
                permission_denied = False
                pass
            if try_again in ('y', 'Y', 'YES', 'Yes', 'yes'):
                try:
                    file_name = input("Where would you like to save: ")
                    temp = open(file_name, 'a')
                    for record in pw_list:
                        temp.write('{0}\n'.format(record))
                    temp.close()
                    print("Your file has been saved to disk.")
                    permission_denied = False
                except PermissionError:
                    permission_denied = True


def check_list(in_list):
    temp_list = []
    if len(in_list) > 0:
        for result in hashcat:
            hash1 = result['hash']
            clear_pw = result['password']
            for parent in in_list:
                try:
                    hash2 = parent['ntlm-hash']
                except KeyError:
                    hash2 = parent['hash']
                username = parent['username']
                if hash1 == hash2:
                    temp_list.append('{0}:{1}'.format(username, clear_pw))
    return temp_list


def list_out(hash_list):
    print('\n[+] Attempting to combine clear-text passwords with their associated usernames.\n')
    save_output = input('Type a filename to save the reunited pairs to file, '
                        'or press enter to display them as standard output: ') or False
    final_results = check_list(hash_list)
    if not save_output:
        print('')
        for result in final_results:
            print(result)
    else:
        print('\nAttempting to save to location: {0}'.format(save_output))
        save_file(save_output, final_results)


file_error = False
file1_cache = []
file2_cache = []

if len(argv) == 3:
    file1 = argv[1]
    file2 = argv[2]
    try:
        for line in open_file(file1):
            file1_cache.append(line.rstrip())

        for line in open_file(file2):
            file2_cache.append(line.rstrip())
    except TypeError:
        print("It looks like something is wrong with your input files.")
        file_error = True
elif len(argv) <= 2:
    print("I don't have enough options to work from. Please feed me your hash dump file and your hashcat output file.")
    file_error = True
else:
    print("How many files are you trying to provide?! I can only take two at this time.")
    file_error = True

files = [file1_cache, file2_cache]

if not file_error:
    for file in files:
        try:
            if len(file[0].split(':')[0]) >= 32:
                print('[+] Clear text passwords found.')
                for line in file:
                    try:
                        temp_dict = {'hash': line.split(':')[0], 'password': line.split(':')[1]}
                        hashcat.append(temp_dict)
                    except IndexError:
                        pass
            elif len(file[0].split(':')[0]) < len(file[0].split(':')[1]) and len(file[0].split(':')[1]) >= 32:
                print('[+] Usernames found in hash list.')
                for line in file:
                    try:
                        temp_dict = {'username': line.split(':')[0], 'hash': line.split(':')[1]}
                        generic.append(temp_dict)
                    except IndexError:
                        pass
            elif len(file[0].split(':')[3]) == 32:
                print('[+] Usernames found in hash list.')
                for line in file:
                    try:
                        temp_dict = {'username': line.split(':')[0], 'uid': line.split(':')[1],
                                     'lm-hash': line.split(':')[2], 'ntlm-hash': line.split(':')[3],
                                     'comment': line.split(':')[4], 'homedir': line.split(':')[5]}
                        pwdump.append(temp_dict)
                    except IndexError:
                        pass
            elif len(file[0].split(':')[1]) > 32:
                print('[+] Usernames found in hash list.')
                for line in file:
                    try:
                        temp_dict = {'username': line.split(':')[0], 'hash': line.split(':')[1],
                                     'uid': line.split(':')[2], 'gid': line.split(':')[3], 'GECOS': line.split(':')[4],
                                     'directory': line.split(':')[5], 'shell': line.split(':')[6]}
                        nixdump.append(temp_dict)
                    except IndexError:
                        pass
            else:
                print('[-] Unable to identify output type. Are you sure you have something with a username?')
        except IndexError:
            pass

if len(hashcat) > 0:
    print("\nLooks like there are some passwords that need to be claimed.")
    if len(pwdump) > 0:
        list_out(pwdump)
    elif len(nixdump) > 0 and len(hashcat) > 0:
        list_out(nixdump)
    elif len(generic) > 0 and len(hashcat) > 0:
        list_out(generic)
    else:
        pass
else:
    print("\nI don't see any cracked hashcat passwords to match.")

#!/usr/bin/env python3
from sys import argv
from os import path


pwdump = []
generic = []
nixdump = []
hashcat = []
file1_cache = []
file2_cache = []
file_error = False


def identify_ntlm(hash_string):
    excluded_letters = ['g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    test_hash = hash_string
    if len(test_hash) == 32:
        ntlm = True
        for letter in excluded_letters:
            if letter in hash_string.lower():
                ntlm = False
        return ntlm


def open_file(file_to_open):
    try:
        temp = open(path.expanduser(file_to_open), 'r')
        temp_list = []
        for record in temp:
            if record != '\n':
                temp_list.append(record)
        temp.close()
        return temp_list
    except FileNotFoundError:
        print('[-] {0} is not a valid file.'.format(file_to_open))


def save_file(file, pw_list):
    try:
        temp = open(path.expanduser(file), 'w')
        for record in pw_list:
            temp.write('{0}\n'.format(record))
        temp.close()
        print("Your file has been saved to disk.")
    except PermissionError:
        permission_denied = True
        while permission_denied:
            print("It is not permissible to save in this location.")
            try_again = input("Is there somewhere else that you would like to try?") or 'No'
            if try_again in ('n', 'N', 'NO', 'No', 'no'):
                permission_denied = False
                pass
            if try_again in ('y', 'Y', 'YES', 'Yes', 'yes'):
                try:
                    file_name = input("Where would you like to save: ")
                    temp = open(path.expanduser(file_name), 'a')
                    for record in pw_list:
                        temp.write('{0}\n'.format(record))
                    temp.close()
                    print("Your file has been saved to disk.")
                    permission_denied = False
                except PermissionError:
                    permission_denied = True
    except FileNotFoundError:
        print("Nope")


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


def incorrect_format():
    try:
        if missing_files:
            pass
        else:
            print('[-] Unknown format error.')
            print('\nPlease use one of these formats in your input files.')
            print('   1. PWDump format: <username>:<rid>:<LM-hash>:<NTLM-hash>:<comment>:<homedir>')
            print('   2. *Nixdump format: <username>:<hash>:<uid>:<gid>:<GECOS>:<directory>:<shell>')
            print('   3. Standard format: <username>:<hash>')
            print('\nAs well as a hashcat potfile.')
            print('   Hashcat potfile: <hash>:<password>\n')
    except NameError:
        print('[-] Unknown format error.')
        print('\nPlease use one of these formats in your input files.')
        print('   1. PWDump format: <username>:<rid>:<LM-hash>:<NTLM-hash>:<comment>:<homedir>')
        print('   2. *Nixdump format: <username>:<hash>:<uid>:<gid>:<GECOS>:<directory>:<shell>')
        print('   3. Standard format: <username>:<hash>')
        print('\nAs well as a hashcat potfile.')
        print('   Hashcat potfile: <hash>:<password>\n')


try:
    input1 = open_file(argv[1])
    input2 = open_file(argv[2])
    for entry in input1:
        file1_cache.append(entry.rstrip())
    for entry2 in input2:
        file2_cache.append(entry2.rstrip())
except IndexError:
    print("[-] Not enough options.")
    print("\nUsage: {0} input1.txt input2.txt\n".format(argv[0]))
    missing_files = True

files = [file1_cache, file2_cache]

if not file_error:
    for file in files:
        try:
            if identify_ntlm(file[0].split(':')[0]):
                print('[+] Clear text passwords found.')
                for line in file:
                    try:
                        temp_dict = {'hash': line.split(':')[0], 'password': line.split(':')[1]}
                        hashcat.append(temp_dict)
                    except IndexError:
                        pass
            elif identify_ntlm(file[0].split(':')[1]):
                print('[+] Usernames found in hash list.')
                for line in file:
                    try:
                        temp_dict = {'username': line.split(':')[0], 'hash': line.split(':')[1]}
                        generic.append(temp_dict)
                    except IndexError:
                        pass
            elif identify_ntlm(file[0].split(':')[3]):
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
                incorrect_format()
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
        print('\nNo username:hash file found to associate with passwords.\n')
        incorrect_format()
else:
    incorrect_format()

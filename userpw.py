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


def save_file(file):
    temp = open(file, 'a')
    for record in combine_pairs():
        temp.write('{0}\n'.format(record))
    temp.close()
    pass


def combine_pairs():
    pw_list = []
    if len(pwdump) > 0:
        for result in hashcat:
            for parent in pwdump:
                if result['hash'] == parent['ntlm-hash']:
                    pw_list.append('{0}:{1}'.format(parent['username'], result['password']))
        if len(pw_list) == 0:
            return "No matches found."
        else:
            return pw_list
    if len(nixdump) > 0:
        for result in hashcat:
            for parent in nixdump:
                if result['hash'] == parent['hash']:
                    pw_list.append('{0}:{1}'.format(parent['username'], result['password']))
        if len(pw_list) == 0:
            return "No matches found."
        else:
            return pw_list
    if len(generic) > 0:
        for result in hashcat:
            for parent in generic:
                if result['hash'] == parent['hash']:
                    pw_list.append('{0}:{1}'.format(parent['username'], result['password']))
        if len(pw_list) == 0:
            return "No matches found."
        else:
            return pw_list
    else:
        return "No matches found."


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
                print('[+] HashCat format detected.')
                for line in file:
                    try:
                        temp_dict = {'hash': line.split(':')[0], 'password': line.split(':')[1]}
                        hashcat.append(temp_dict)
                    except IndexError:
                        pass
            elif len(file[0].split(':')[0]) < len(file[0].split(':')[1]) and len(file[0].split(':')[1]) >= 32:
                print('[+] Generic format detected.')
                for line in file:
                    try:
                        temp_dict = {'username': line.split(':')[0], 'hash': line.split(':')[1]}
                        generic.append(temp_dict)
                    except IndexError:
                        pass
            elif len(file[0].split(':')[3]) == 32:
                print('[+] PWDump format detected.')
                for line in file:
                    try:
                        temp_dict = {'username': line.split(':')[0], 'uid': line.split(':')[1],
                                     'lm-hash': line.split(':')[2], 'ntlm-hash': line.split(':')[3],
                                     'comment': line.split(':')[4], 'homedir': line.split(':')[5]}
                        pwdump.append(temp_dict)
                    except IndexError:
                        pass
            elif len(file[0].split(':')[1]) > 32:
                print('[+] NIXDump format detected.')
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
    print("\nLooks like there are some passwords that need to be reunited with their username.")
    if len(pwdump) > 0 and len(hashcat) > 0:
        save_output = input("Type a filename to save the reunited pairs to file, "
                            "or press enter to display them as standard output: ")
        if save_output == '':
            print("")
            final_results = combine_pairs()
            for result in final_results:
                print(result)
        else:
            print("\nWriting to file: {0}".format(save_output))
            save_file(save_output)
    elif len(nixdump) > 0 and len(hashcat) > 0:
        save_output = input("Type a filename to save the reunited pairs to file, "
                            "or press enter to display them as standard output: ")
        if save_output == '':
            print("")
            final_results = combine_pairs()
            for result in final_results:
                print(result)
        else:
            print('\nWriting to file: {0}'.format(save_output))
            save_file(save_output)
    elif len(generic) > 0 and len(hashcat) > 0:
        save_output = input("Type a filename to save the reunited pairs to file, "
                            "or press enter to display them as standard output: ")
        if save_output == '':
            print("")
            final_results = combine_pairs()
            for result in final_results:
                print(result)
        else:
            print('\nWriting to file: {0}'.format(save_output))
            save_file(save_output)
    else:
        pass
else:
    print("\nI don't see any cracked hashcat passwords to match.")

#!/usr/bin/env python3
from sys import argv

pwdump = []  # format= <username>:<uid>:<LM-hash>:<NTLM-hash>:<comment>:<homedir>
generic = []  # format= <username>:<hash>
nixdump = []  # format= <username>:<hash>:<uid>:<gid>:<GECOS>:<directory>:<shell>
hashcat = []  # format= <hash>:<password>


def open_file(file):
    try:
        temp = open(file, 'r')
        temp_dict = []
        for record in temp:
            temp_dict.append(record)
        temp.close()
        return temp_dict
    except FileNotFoundError:
        print('Unable to locate {0}'.format(file))


def save_file(file):
    temp = open(file, 'a')
    for record in combine_pairs():
        temp.write('{0}\n'.format(record))
    temp.close()
    pass


def combine_pairs():
    pw_dict = []
    if len(pwdump) > 0:
        for result in hashcat:
            for parent in pwdump:
                if result['hash'] == parent['ntlm-hash']:
                    pw_dict.append('{0}:{1}'.format(parent['username'], result['password']))
        return pw_dict
    if len(nixdump) > 0:
        for result in hashcat:
            for parent in nixdump:
                if result['hash'] == parent['hash']:
                    pw_dict.append('{0}:{1}'.format(parent['username'], result['password']))
    if len(generic) > 0:
        for result in hashcat:
            for parent in generic:
                if result['hash'] == parent['hash']:
                    pw_dict.append('{0}:{1}'.format(parent['username'], result['password']))
    else:
        return ''


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
            if len(file[0].split(':')[1]) < len(file[0].split(':')[2]):
                print('[+] PWDump format detected.')
                for line in file:
                    temp_dict = {'username': line.split(':')[0], 'uid': line.split(':')[1],
                                 'lm-hash': line.split(':')[2], 'ntlm-hash': line.split(':')[3],
                                 'comment': line.split(':')[4], 'homedir': line.split(':')[5]}
                    pwdump.append(temp_dict)
            elif len(file[0].split(':')[1]) > len(file[0].split(':')[2]):
                print('[+] NIXDump format detected.')
                for line in file:
                    temp_dict = {'username': line.split(':')[0], 'hash': line.split(':')[1],
                                 'uid': line.split(':')[2], 'gid': line.split(':')[3], 'GECOS': line.split(':')[4],
                                 'directory': line.split(':')[5], 'shell': line.split(':')[6]}
                    nixdump.append(temp_dict)
        except IndexError:
            if len(file[0].split(':')[0]) > len(file[0].split(':')[1]):
                print('[+] HashCat format detected.')
                for line in file:
                    temp_dict = {'hash': line.split(':')[0], 'password': line.split(':')[1]}
                    hashcat.append(temp_dict)
            elif len(file[0].split(':')[0]) < len(file[0].split(':')[1]):
                print('[+] Generic format detected.')
                for line in file:
                    temp_dict = {'username': line.split(':')[0], 'hash': line.split(':')[1]}
                    generic.append(temp_dict)
            else:
                print('[-] Unable to identify output type. Are you sure you have something with a username?')

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
        print("NIXDump username:password output:")
    elif len(generic) > 0 and len(hashcat) > 0:
        print("Generic username:password output:")
    else:
        print("Unknown Result")
else:
    pass

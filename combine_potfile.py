#!/usr/bin/env python3

import argparse
import re as regex
    
def identify_ntlm(hash):
    reg = r'[g-zG-Z]'
    if (not regex.search(reg,hash)) and (len(hash) == 32):
        return True
    else:
        return False

def compile_list(input,type='generic'):
    compiled_list = []
    choices = ['potfile','pwdump','nixdump','generic']
    if not type in choices:
        return False
    if type == 'potfile':
        info = [
            {'name':'hash','position':0},
            {'name':'password','position':1}
            ]
    elif type == 'pwdump':
        info = [
            {'name':'username','position':0},
            {'name':'uid','position':1},
            {'name':'lm_hash','position':2},
            {'name':'ntlm_hash','position':3},
            {'name':'comment','position':4},
            {'name':'home_dir','position':5}
            ]
    elif type == 'nixdump':
        info = [
            {'name':'username','position':0},
            {'name':'hash','position':1},
            {'name':'uid','position':2},
            {'name':'gid','position':3},
            {'name':'gecos','position':4},
            {'name':'directory','position':5},
            {'name':'shell','position':6}
            ]
    elif type == 'generic':
        info = [
            {'name':'username','position':0},
            {'name':'hash','position':1}
            ]
    try:
        with open(input,'r') as input_file:
            for line in input_file:
                line_items = line.split(':')
                line_info = {}
                try:
                    for item in info:
                        line_info[item['name']] = line_items[item['position']].strip()
                    compiled_list.append(line_info)
                except IndexError:
                    return False
    except FileNotFoundError:
        return '[!] Unable to locate file: \'{0}\''.format(input)
    return compiled_list

def join_list(potfile,user_list):
    for key in user_list[0].keys():
        if 'hash' in key:
            temp_hash = key
            if identify_ntlm(user_list[0][temp_hash]):
                hash_key = key
    try:
        if hash_key:
            pass
    except KeyError:
        return False
    list_join = []
    for user in user_list:
        pw_found = False
        for pw in potfile:
            if user[hash_key] == pw['hash']:
                pw_found = True
                list_join.append('{0}:{1}'.format(user['username'],pw['password']))
        if not pw_found:
            list_join.append('{0}:'.format(user['username']))
    return list_join

def main():
    return_users = []
    desc = None
    epi = None
    parser = argparse.ArgumentParser(description=desc,epilog=epi)
    parser.add_argument('-i','--infile',help='generic username:hash input file')
    parser.add_argument('--pwdump',help='pwdump input file')
    parser.add_argument('--potfile',help='hashcat potfile input file',required=True)
    parser.add_argument('--nixdump',help='nixdump input file')
    parser.add_argument('-o','--outfile',help='save results to a file')
    parser.add_argument('--force',help='overwrite existing file',action='store_true')
    args = parser.parse_args()
    pwdump_list = None
    potfile_list = None
    nixdump_list = None
    generic_list = None
    if args.pwdump:
        pwdump_list = compile_list(args.pwdump,'pwdump')
        if not pwdump_list:
            return '[!] Unable to parse pwdump input'
    if args.potfile:
        potfile_list = compile_list(args.potfile,'potfile')
        if not potfile_list:
            return '[!] Unable to parse potfile input'
    if args.nixdump:
        nixdump_list = compile_list(args.nixdump,'nixdump')
        if not nixdump_list:
            return '[!] Unable to parse nixdump input'
    if args.infile:
        generic_list = compile_list(args.infile,'generic')
        if not generic_list:
            return '[!] Unable to parse input file'
    if potfile_list and (pwdump_list or nixdump_list or generic_list):
        if pwdump_list:
            try:
                for result in join_list(potfile_list,pwdump_list):
                    return_users.append(result)
            except:
                if type(pwdump_list) == str:
                    return pwdump_list
                else:
                    return potfile_list
        elif nixdump_list:
            try:
                for result in join_list(potfile_list,nixdump_list):
                    return_users.append(result)
            except:
                if type(nixdump_list) == str:
                    return nixdump_list
                else:
                    return potfile_list
        else:
            try:
                for result in join_list(potfile_list,generic_list):
                    return_users.append(result)
            except:
                if type(generic_list) == str:
                    return generic_list
                else:
                    return potfile_list
    else:
        return '[!] Missing proper input files'
    if args.outfile:
        if args.force:
            mode = 'w'
        else:
            mode = 'x'
        try:
            with open(args.outfile,mode) as new_file:
                for item in return_users:
                    new_file.writelines('{0}\r\n'.format(item))
            return '[+] Results have been saved to file: \'{0}\''.format(args.outfile)
        except FileExistsError:
            return '[!] File exists. Use --force to overwrite file.'
    else:
        return return_users

if __name__ == '__main__':
    result = main()
    if type(result) == list:
        for item in result:
            print(item)
    else:
        print(result)
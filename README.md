# Problem Statement:

You have a pwdump file of thousands of users. After cracking many with hashcat, you are left with a hashcat.potfile that is in the format of hash:password, but is not tied to the usernames in the original list.

**Sample pwdump.txt**  
```
Chris:1001:NO LM-HASH**********************:336dd04ddff33322cdf87bb1373dbeab:::
thr33per:1002:NO LM-HASH**********************:e7c737357ef619989eb2db501e560164:::
admin-chris:1010:NO LM-HASH**********************:bbb3a65506f6a04f1158e05ba0e34280:::
cbooth:1012:NO LM-HASH**********************:e79b80db674a601b9c1f84a3b3980402:::
```

**Sample hashcat.potfile**
```
336dd04ddff33322cdf87bb1373dbeab:SuperSecret1
e7c737357ef619989eb2db501e560164:TellN01!!2019
e79b80db674a601b9c1f84a3b3980402:Password2014
```

# Solution:

This script takes two input files (A password hash dump file, and a hashcat output file) and combines all clear text passwords back to their associated users.

To use this, you can use the command line as noted below

`$ python joinpw2user.py input1.txt input2.txt`
or `$ ./joinpw2user.py input1.txt input2.txt`

The script allows you to save the results out to a file, or display them on standard output.

**Sample script output**  
```
$ python joinpw2user.py pwdump.txt ~/.hashcat/hashcat.potfile
[+] Usernames found in hash list.
[+] Clear text passwords found.

Looks like there are some passwords that need to be claimed.

[+] Attempting to combine clear-text passwords with their associated usernames.

Type a filename to save the reunited pairs to file, or press enter to display them as standard output:

Chris:SuperSecret1  
thr33per:TellN01!!2019  
cbooth:Password2014  
```

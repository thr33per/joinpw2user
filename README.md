# userpw
###### Adds hashcat cleartext passwords back to the user list.
This script takes two input files (A password hash dump file, and a hashcat output file) and combines all clear text passwords back to their associated users.

To use this, you can use the command line as noted below

`$ python userpw.py input1.txt input2.txt`
or `$ ./userpw.py input1.txt input2.txt`

The script allows you to save the results out to a file, or display them on standard output.

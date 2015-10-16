######################################################################
######################################################################
##
##	David Tran, Cole Rees
##	Assignment 3 - COMP 8006
##	Thursday, March 13 2014
##
##	Introduction to IDS Implementation README
##
######################################################################
######################################################################

This file is to describe the initialization of our assignment.

The script will require manual execution once. Afterwards, if all user-
defined settings are correct and appropriate, will execute automatically
through crontab. Optimal execution periods are 30 seconds apart.

Before initial execution, make sure to note the directory the shell script
will reside in. The shell script will not change its directory manually as
all directories specified in the original shell script are absolute paths.

For ease of access and purpose, our testing and original directories reside
in the /root/Downloads directory. To change this, retrieve the residing 
directory you wish to place the shell script, and change current paths to
the new one. These user-defined variables are of interest:

	BAN_LIST="/root/Downloads/banned.txt"
	HOLDER="/root/Downloads/tmp.txt"
	TEMP_LIST="/root/Downloads/temp.txt"

	firstJob="* * * * * /root/Downloads/shell_script.sh"
	secondJob="* * * * * ( sleep 30 ; /root/Downloads/shell_script.sh )"

Other user-defined variables include:
	
	MAX_FAILED_ATTEMPTS=2 # attempts
	BAN_LENGTH="30 seconds" # adds this duration to our current time
	READ_LAST=100 # lines in our log file

These variables specify the functionality of the IDS.

Finally, to execute the shell script, navigate to its directory and (after
giving proper execution permissions) run this command:

	./shell_script.sh

For more information on initializing the IDS, please consult the script file
as well as the Design Work & Testing document.

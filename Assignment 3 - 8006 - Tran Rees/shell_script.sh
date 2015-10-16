#!/bin/bash

################################################################################
#------------------------------------------------------------------------------#
#
#	Filename: 	shell_script.sh
#
#	Authors:	David Tran - A00801942
#			Cole Rees  - A00741578
#
#	Date:		Thursday, March 13 2014
#
#	Usage:		./shell_script.sh
#
#------------------------------------------------------------------------------	
#	
#	Description: 	Utilizes monitoring capabilities alongside iptables
#			and crontab to detect potential SSH attacks through
#			failed passwords.
#
#		        Note: Editing the logic and implementation may not
#			allow the IDS to function according to criteria. Edit
#			at your discretion. You have been warned.
#
#------------------------------------------------------------------------------#
################################################################################

#------------------------------------------------------------------------------#
#--------------------------- USER DEFINED VARIABLES ---------------------------#
#------------------------------------------------------------------------------#

################################################################################
#
# BAN_LIST
#
# The directory in which the user can specify to look for hostile hosts. This
# file keeps track of the hostile host's IP, the time it will be unbanned, and 
# its status, which is either BANNED or UNBANNED. Default value of BAN_LENGTH
# will result in no usage of the BAN_LIST.

BAN_LIST="/root/Downloads/banned.txt"

################################################################################
# 
# HOLDER and TEMP_LIST
#
# The directories in which the user can specify temporary files that hold values
# retrieved from actions and utilities such as AWK. These files aren't so
# important in terms of keeping information. Their main function is to hold
# filtered values per logic iteration.

HOLDER="/root/Downloads/tmp.txt"
TEMP_LIST="/root/Downloads/temp.txt"

################################################################################

################################################################################
#
# firstJob and secondJob
#
# A clever implementation of cronjobs that allows a 30-second interval between
# two jobs. It is important to note that the directories must match where this
# script is located and it must reflect in these two user-defined variables.

firstJob="* * * * * /root/Downloads/shell_script.sh"
secondJob="* * * * * ( sleep 30 ; /root/Downloads/shell_script.sh )"

################################################################################

################################################################################
#
# MAX_FAILED_ATTEMPTS
# 
# The amount of times a host can be able to fail on password attempts before being
# banned. 

MAX_FAILED_ATTEMPTS=2 # attempts

################################################################################

################################################################################
#
# BAN_LENGTH
#
# The length of time a ban lasts. Default values are considered to be indefinite 
# bans. 

BAN_LENGTH="30 seconds"

################################################################################

################################################################################
#
# READ_LAST
#
# This user-defined variable sets the range of how far back the script will read
# the log file. The smaller it is, the more of a recent check is emphasized. The
# larger the number, the farther back and the more of a history check is 
# emphasized.

READ_LAST=100 # lines in our log file

################################################################################

################################################################################
#
# LOG_FILE
#
# For future implementation of multiple log files.
#
# Specifying which log files to monitor.

LOG_FILE=/var/log/secure

################################################################################

#------------------------------------------------------------------------------#
#----------------------- END OF USER-DEFINED VARIABLES ------------------------#
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
#-------------------------- Preliminary Setup - DFT!! -------------------------#
#------------------------------------------------------------------------------#
firstFlag=0
secondFlag=0

touch temp.txt
crontab -l > temp.txt
while read line;
do
	if [ "$line" == "$firstJob" ]; then
		firstFlag=1
	fi

	if [ "$line" == "$secondJob" ]; then
		secondFlag=1
	fi
done < temp.txt

if [ $firstFlag = 0 ]; then
	(crontab -l; echo "$firstJob") | crontab -
fi

if [ $secondFlag = 0 ]; then
	(crontab -l; echo "$secondJob") | crontab -
fi
rm temp.txt

# Helper timestamp functions to keep track of bans
# formatting should stay the same for comparison
banstamp() {
  date --date "$BAN_LENGTH" +"%s"
}

readable_stamp() {
  date --date "$BAN_LENGTH" +"%b-%d %T"	
}

timestamp() {
  date +"%s"
}

# Check if our banlist exists already. If not, create it.
if [ -e "$BAN_LIST" ]
then
	echo "$BAN_LIST found." > /dev/null
else
	echo "$BAN_LIST not found. Creating..." > /dev/null
	touch $BAN_LIST
fi
################################################################################
#------------------------------------------------------------------------------#
#------------------------ LOGIC IMPLEMENTATION - DFT!! ------------------------#
#------------------------------------------------------------------------------#
################################################################################

#==============================================================================#

################################################################################
#------------------------------------------------------------------------------#
#-------------------- IDS - SSH Failed Attempts Detection ---------------------#
#------------------------------------------------------------------------------#
################################################################################

# Read in the log files
tail -$READ_LAST $LOG_FILE | awk -v max_fail="$MAX_FAILED_ATTEMPTS" '/sshd/ && /Failed password for/ { if (/invalid user/) try[$13]++; else try[$11]++; }
END { for (h in try) if (try[h] > max_fail) print h; }' |
while read ip
do
	# note: check if IP is already blocked...
	/sbin/iptables -L -n | grep $ip > /dev/null
	if [ -z "$BAN_LENGTH" ] ; then
		# indefinite block, don't even log it into our ban list
		/sbin/iptables -L -n | grep $ip > /dev/null
		if [ $? != 0 ] ; then
			logger -p authpriv.notice "*** Blocking SSH attempt from: $ip indefinitely"
			/sbin/iptables -I INPUT -s $ip -j DROP
		fi
	else
		if [ $? != 0 ] ; then # If $? == 0, then it is already blocked; do nothing. Otherwise, there's something we should do.
			# check if it's a previously blocked and then unblocked IP
			(awk "/$ip/" < $BAN_LIST) > $HOLDER
			banTime=( $(tail -1 $HOLDER | awk '{print $2}') )
			status=( $(tail -1 $HOLDER | awk '{print $3}') )
			current_time=$(timestamp)

			# There is a record in our ban list since the "status" is not null. Check if it is a recent offense.
			if [ -n "$status" ] ; then
				# If the status is BANNED, do nothing.
				if (( "$status" == "UNBANNED" && $banTime < $current_time )) ; then
					touch $TEMP_LIST
					(awk "/sshd/ && /Failed password for/ && /$ip/" < $LOG_FILE) > $TEMP_LIST
					month=( $(tail -1 $TEMP_LIST | awk '{print $1}') )
					day=( $(tail -1 $TEMP_LIST | awk '{print $2}') )
					time=( $(tail -1 $TEMP_LIST | awk '{print $3}') )
					time_of_offense="$month $day $time"	
					newDate=( $(date -d "$time_of_offense $BAN_LENGTH" +%s) )
					if (( $newDate >= $current_time )) ; then 
					# the offending time is greater than current time, so it is recent. Block it and log it.
						banUntil=$(banstamp)
						readable_time=$(readable_stamp)
						logger -p authpriv.notice "*** Blocking SSH attempt from: $ip until $readable_time"
						/sbin/iptables -I INPUT -s $ip -j DROP
						echo "$ip $banUntil BANNED" >> $BAN_LIST
					fi
					rm $TEMP_LIST
				fi		
			else # Never blocked before, so it must be a first offense; block it and log it.
				# if empty, that means we haven't blocked it yet
				banUntil=$(banstamp)
				readable_time=$(readable_stamp)
				logger -p authpriv.notice "*** Blocking SSH attempt from: $ip until $readable_time"
				/sbin/iptables -I INPUT -s $ip -j DROP
				echo "$ip $banUntil BANNED" >> $BAN_LIST
			fi
			rm $HOLDER
		fi
	fi
done

################################################################################
#------------------------------------------------------------------------------#
#---------------------- Unbanning & Time Expiry Handling ----------------------#
#------------------------------------------------------------------------------#
################################################################################

# read the banlist, internal seperator is a space
while IFS=' ': read ipAddr bannedUntil curStatus
do
	# check the timestamps for each ip
	banned_ip=$ipAddr
	banned_until=$bannedUntil
	currentStatus=$curStatus
	current_date=$(timestamp)

	# if the timestamps are expired
	if [ "$currentStatus" = "BANNED" ];
	then
		# echo $banned_ip $current_date $banned_until $currentStatus 
		# echo "Ban time for $banned_ip is expired. Unbanning..."
		/sbin/iptables -L -n | grep $ipAddr > /dev/null
		if [ $current_date -ge $banned_until ]; then
			if [ $? -eq 0 ] ; then
				# run iptables -D specific rule
				logger -p authpriv.notice "*** Unblocking: $ipAddr"
				/sbin/iptables -D INPUT -s $ipAddr -j DROP
				(awk "/$ipAddr/" < $BAN_LIST) > $HOLDER
				time=( $(tail -1 $HOLDER | awk '{print $2}') )
				status=( $(tail -1 $HOLDER | awk '{print $3}') )
				line="$ipAddr $time $status"
				newLine="$ipAddr $time UNBANNED"
				sed -i "/$line/c $newLine" $BAN_LIST
				rm $HOLDER
			fi
		fi
	else
		continue
	fi
done < $BAN_LIST

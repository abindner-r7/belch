#!/bin/bash
##
# Created 2015-10-16 by schlpr0k
#
# Purpose: burpies.sh is a Burp Suite XML parser to automate tables  used in reporing.
#
# Usage: After using the scanning with Burp Suite, do the following: 
# --> Select all of the sites on the left. This will display all of the collective findings on the right. 
# --> Select all of the vulnerabilities on the right. DO NOT include False Positives if marked. 
# --> Right click on the highlighted list and select "Report".
# --> Generate an XML report. DO NOT include the packets! This may alter the results of the scripts.
#
# -----> Syntax: ./burpies.sh filename.xml
#
# --> Files generated based on individual modules below. 
###

bfile=${1?"The name of the Burp Suite XML file is required!"}

##--Begin Vulnerability Module--##

vuln_title=XSS
vuln_desc="<name>Cross-site scripting"
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<host ip" |cut -d'"' -f2 > /tmp/b001.txt
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<host ip" |cut -d'>' -f2 |cut -d'<' -f1 > /tmp/b002.txt
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<path" |cut -d"[" -f3 | cut -d"]" -f1 > /tmp/b003.txt
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<location" |cut -d"[" -f4 | cut -d"]" -f1 > /tmp/b004.txt

##Set staging file##
touch /tmp/stage.data

##Set Counter##
counter=$(cat /tmp/b001.txt| wc -l)

##If counter is greater than "0" process the rest of the module##
if [ $counter -gt 0 ]
then
    ##Combine temp files into the staging file##
    for (( c=1; c<=$counter; c++ )); do echo $(sed -n $(echo $c)p /tmp/b001.txt),$(sed -n $(echo $c)p /tmp/b002.txt),$(sed -n $(echo $c)p /tmp/b003.txt),$(sed -n $(echo $c)p /tmp/b004.txt)>>/tmp/stage.data; done
    ##Set header and write final file##
    ###Echo line below may need to change per module###
    echo IP Address,Site,Path,Vulnerable Parameter >>Burpies-$(echo $vuln_title).csv
    cat /tmp/stage.data |sort -u >>Burpies-$(echo $vuln_title).csv
    echo $vuln_title complete...
else
    echo $vuln_title counter returned zero results. No file created.
fi

##Clean up temp files##
rm -f /tmp/stage.data /tmp/b00*.txt

##--End Vulnerability Module--##

##--Begin Vulnerability Module--##

vuln_title=Autocomplete
vuln_desc="<name>Password field with autocomplete enabled"
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<host ip" |cut -d'"' -f2 > /tmp/b001.txt
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<host ip" |cut -d'>' -f2 |cut -d'<' -f1 > /tmp/b002.txt
grep "$(echo $vuln_desc)" $bfile -A 3 | grep "<path" |cut -d"[" -f3 | cut -d"]" -f1 > /tmp/b003.txt

##Set staging file##
touch /tmp/stage.data

##Set Counter##
counter=$(cat /tmp/b001.txt| wc -l)

##If counter is greater than "0" process the rest of the module##
if [ $counter -gt 0 ]
then
    ##Combine temp files into the staging file##
    for (( c=1; c<=$counter; c++ )); do echo $(sed -n $(echo $c)p /tmp/b001.txt),$(sed -n $(echo $c)p /tmp/b002.txt),$(sed -n $(echo $c)p /tmp/b003.txt)>>/tmp/stage.data; done
    ##Set header and write final file##
    ###Echo line below may need to change per module###
    echo IP Address,Site,Path >>Burpies-$(echo $vuln_title).csv
    cat /tmp/stage.data |sort -u >>Burpies-$(echo $vuln_title).csv
    echo $vuln_title complete...
else
    echo $vuln_title counter returned zero results. No file created.
fi

##Clean up temp files##
rm -f /tmp/stage.data /tmp/b00*.txt

##--End Vulnerability Module--##

~/tools/burpies-mod-httponly.sh $bfile
~/tools/burpies-mod-secure.sh $bfile


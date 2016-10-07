#!/bin/bash

##--Begin Vulnerability Module--##
bfile=${1?"The name of the Burp Suite XML file is required!"}

vuln_title=Secure
vuln_desc="<name>SSL cookie without secure flag"

##Set staging file##
touch /tmp/stage.data

##Load staging file with data##
for site in `echo $(grep "<host " $bfile |sort -u |tr ' ' ':' |cut -d'>' -f2 |cut -d'<' -f1)`
do
    var1=$(grep "$(echo $vuln_desc)" $bfile -A 15 |grep $site -A 14 |grep "<issueDetailItem>" |cut -d '[' -f3 |cut -d'=' -f1 |sort -u |tr '\n' '|')
    var1=${var1%?}
    if [ $(echo $var1 |wc -c) -gt 1 ]
    then 
        echo $site",Secure,"$var1 >>/tmp/stage.data
    fi
    var1=
done

##Build Output File##
counter=$(cat /tmp/stage.data |wc -l)
if [ $counter -gt 0 ]
then
echo "Site,Missing Header,Vulnerable Cookie(s)" >>Burpies-$(echo $vuln_title).csv
cat /tmp/stage.data >>Burpies-$(echo $vuln_title).csv
echo $vuln_title complete...
else
    echo $vuln_title counter returned zero results. No file created.
fi

##Clean up temp files##
rm -f /tmp/stage.data

##--End Vulnerability Module--##

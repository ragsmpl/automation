#!/bin/bash
##############################################################################################################################
###########################      This script detects the log4j vulnerebility CVE-2021-44228         ##########################
########################### referred https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b ########################
##############################################################################################################################

#Get all the path where log4j core jar is present
filepath=$(find / -name "log4j-core-*.jar")
echo -e "\n\n"
echo -e "Scanning for vulnerability CVE-2021-44228......\n"
sleep 5;

#check the version of the log4j jar and suggest what are the mitigation steps that has to be taken.
if [ $(echo $filepath | rev | cut -d'/' -f1 | cut -d '.' -f '2-'| rev | grep -oE 2\.?[0-9][1-4]*\.[[:alnum:]]*) ]
   then 
       if [ $(echo $filepath | rev | cut -d'/' -f1 | cut -d '.' -f '2-'| rev | grep -oE 2\.?[0-9][1-4]*\.[[:alnum:]]*) ]
           then
               echo -e "##########################################################"; 
               echo -e "CRITICAL: Log4j vulnerable version $(echo $filepath | rev | cut -d'/' -f1 | cut -d '.' -f '2-'| rev | grep -oE 2\.?[0-9][1-4]*\.[[:alnum:]]*) found!!!"; 
               echo "NEXT STEPS: For releases >=2.0-beta9 and <=2.10.0, the mitigation is to remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class."
               echo -e "##########################################################"; 
               echo -e "\n\n"
               #confirm if JndiLookup.class exists and execute below commands
               #if [  -n "$(uname -a | grep Ubuntu)" ]; then
                #     apt-get install -y unzip
                #     apt-get install -y zip
               #else
                #     yum install -y unzip
                 #    yum install -y zip
               #fi  
               #if [ $(unzip -l $filepath | grep -i --color=always JndiLookup.class) ]
                   #then
                       #zip -q -d $filepath org/apache/logging/log4j/core/lookup/JndiLookup.class
               #fi              
               
        else
               echo -e "##########################################################"; 
               echo -e "CRITICAL: Log4j vulnerable version $(echo $filepath | rev | cut -d'/' -f1 | cut -d '.' -f '2-'| rev | grep -oE 2\.?[0-9][1-4]*\.[[:alnum:]]*) found!!!"; 
               echo "NEXT STEPS: In releases >=2.10, this behavior can be mitigated by setting either the system property log4j2.formatMsgNoLookups or the environment variable LOG4J_FORMAT_MSG_NO_LOOKUPS to true"
               echo -e "##########################################################"; 
               echo -e "\n\n"
               #execute below commands
               #echo "LOG4J_FORMAT_MSG_NO_LOOKUPS=true" >>/etc/environment
               #source /etc/environment
        fi
      
elif [ $( echo $filepath  | rev | cut -d'/' -f1 | cut -d '.' -f '2-'| rev | grep -E -- '2.0-rc2|2.0-rc1|2.0-beta9') ]; 
    then 
        echo -e "##########################################################"; 
        echo -e "CRITICAL: Log4j vulnerable version $(echo $filepath  | rev | cut -d'/' -f1 | cut -d '.' -f '2-'| rev | grep -E -- '2.0-rc2|2.0-rc1|2.0-beta9') found!!!"; 
        echo "NEXT STEPS: For releases >=2.0-beta9 and <=2.10.0, the mitigation is to remove the JndiLookup class from the classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class"
        echo -e "##########################################################"; 
        echo -e "\n\n"
        ##confirm if JndiLookup.class exists and execute below commands
         #if [  -n "$(uname -a | grep Ubuntu)" ]; then
                #     apt-get install -y unzip
                #     apt-get install -y zip
               #else
                #     yum install -y unzip
                 #    yum install -y zip
        #fi  
        #if [ $(unzip -l $filepath | grep -i --color=always JndiLookup.class) ]
             #then
                  #zip -q -d $filepath org/apache/logging/log4j/core/lookup/JndiLookup.class
        #fi   
else 
     echo -e "##########################################################"; 
     echo -e "INFO: Log4j vulnerable version of log4j core jar not found!! "; 
     echo -e "##########################################################"; 
     echo -e "\n\n"
fi

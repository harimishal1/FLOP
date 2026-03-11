#!/bin/bash

# This script just loads and unloads the
# enable-dc-civac kext repeatedly, in hopes
# that it will get scheduled at least once for 
# all the P-cores. 
for i in {1..30}
do
    sudo kextload /Library/Extensions/enable-dc-civac.kext 2>/dev/null
    sudo kextunload /Library/Extensions/enable-dc-civac.kext 2>/dev/null    
done

# Confirm that the kext ran several times by searching
# the system log.
# sudo log show --last 2m | grep enable-dc-civac  

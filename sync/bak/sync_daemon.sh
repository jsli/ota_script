#!/bin/bash

USER_NAME=srv-release
PASSWORD="ZPu9uPt2)n*tLV(~DRQ9"

REMOTE_SERVER=//sh2-filer02/Release
LOCAL_ROOT=/home/manson/OTA
LOCAL_MIRROR=$LOCAL_ROOT/release/CP/CP_SERVER_MIRROR
LOCAL_RELEASE=$LOCAL_ROOT/LOCAL_RELEASE

EXCLUDE_FILE=exclude.list

#mount remote server
sudo umount $REMOTE_SERVER
sudo mount -t smbfs -o username=$USER_NAME,password=$PASSWORD $REMOTE_SERVER $LOCAL_MIRROR

#rsync cp images
#while true
#do
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL/HLTD $LOCAL_RELEASE
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL/HLWB $LOCAL_RELEASE
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL_DSDS/HLTD_DSDS $LOCAL_RELEASE
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL_DSDS/HLWB_DSDS $LOCAL_RELEASE
#    sleep 10
#done

#!/bin/bash

LOCAL_ROOT=/home/manson/OTA
LOCAL_MIRROR=$LOCAL_ROOT/release/CP/CP_SERVER_MIRROR
LOCAL_RELEASE=$LOCAL_ROOT/release/CP/CP_SYNC
EXCLUDE_FILE=exclude.list
    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL/HLTD $LOCAL_RELEASE/HL
#rsync cp images
#while true
#do
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL/HLTD $LOCAL_RELEASE
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL/HLWB $LOCAL_RELEASE
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL_DSDS/HLTD_DSDS $LOCAL_RELEASE
#    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $LOCAL_MIRROR/HL_DSDS/HLWB_DSDS $LOCAL_RELEASE
#    sleep 10
#done

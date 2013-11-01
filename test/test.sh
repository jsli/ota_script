#!/bin/bash

EXCLUDE_FILE=/home/manson/OTA/scripts/test/exclude.list
REMOTE_DIR=/home/manson/OTA/scripts/test/release/
LOCAL_DIR=/home/manson/OTA/scripts/test/local/

while true
do
    rsync -q -p -o -g --delete -avzh --include="*.bin" --exclude-from=$EXCLUDE_FILE $REMOTE_DIR $LOCAL_DIR
    sleep 10
done

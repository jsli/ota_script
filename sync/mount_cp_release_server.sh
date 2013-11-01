#!/bin/bash

USER_NAME=srv-release
PASSWORD="ZPu9uPt2)n*tLV(~DRQ9"

REMOTE_SERVER=//sh2-filer02/Release
LOCAL_MIRROR=$OTA_ROOT/release/CP/CP_SERVER_MIRROR

#mount remote server
sudo umount $REMOTE_SERVER
sudo mount -t smbfs -o username=$USER_NAME,password=$PASSWORD $REMOTE_SERVER $LOCAL_MIRROR

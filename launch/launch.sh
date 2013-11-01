#!/bin/bash

#mount cp release server
sudo $OTA_SCRIPT_ROOT/sync/mount_cp_release_server.sh

#run daemon container
supervisord

#run revel
revel run github.com/jsli/ota/radio prod > /dev/null &

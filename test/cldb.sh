#!/bin/bash

mysql -uroot ota -plijinsong -e "delete from cp_release"
rm -rf /home/manson/OTA/scripts/test/local/*

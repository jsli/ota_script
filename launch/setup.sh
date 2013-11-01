#!/bin/bash

#setup for supervisor
mkdir $OTA_ROOT/tmp/supervisor
mkdir $OTA_ROOT/logs/supervisor

#build package
go install $GOPATH/src/github.com/jsli/cp_release/main/scanner.go
go install $GOPATH/src/github.com/jsli/cp_release/main/monitor.go

#!/bin/bash

SDB=/Users/changjoonbaek/tizen-studio/tools/sdb

DISPLAY=:0 /Users/changjoonbaek/tizen-studio/tools/emulator/bin/em-cli launch -n M-3.0-x86

sleep 20

$SDB root on
$SDB push /Users/changjoonbaek/Docker/ttrace* /tmp
$SDB shell 'rpm -Uvh --nodeps --force /tmp/*.rpm'
$SDB shell 'atrace freq'

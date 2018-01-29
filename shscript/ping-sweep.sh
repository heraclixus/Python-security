#!/bin/bash

for ip in $(seq 1 254); do
    ping -c 1 192.168.0.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done 
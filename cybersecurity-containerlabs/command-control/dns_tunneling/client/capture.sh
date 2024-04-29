#!/bin/bash

python dns_lookup.py &
touch captures/capture.pcapng
tshark -ni any -w captures/capture.pcapng
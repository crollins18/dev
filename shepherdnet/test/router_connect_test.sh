#!/bin/sh

# Test host-leaf connectivity
docker exec clab-shepherdnet-leaf1 ping clab-shepherdnet-spine1 -c 1
docker exec clab-shepherdnet-leaf1 ping clab-shepherdnet-spine2 -c 1
docker exec clab-shepherdnet-leaf2 ping clab-shepherdnet-spine1 -c 1
docker exec clab-shepherdnet-leaf2 ping clab-shepherdnet-spine2 -c 1
docker exec clab-shepherdnet-leaf3 ping clab-shepherdnet-spine1 -c 1
docker exec clab-shepherdnet-leaf3 ping clab-shepherdnet-spine2 -c 1
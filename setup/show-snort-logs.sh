#!/bin/bash
printf "Showing live NIDS alerts:\n\n"
docker logs --follow --tail=0 snort3
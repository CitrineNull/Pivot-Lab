#!/bin/bash
for interface in $interfaces;
do
  /snort/bin/snort -c /snort/etc/snort/snort.lua -R /snort/rules/ -A full -k none -i $interface &
done

# Needed to keep process alive since the snort processes all go to the background (thx docker <3)
sleep infinity

#! /bin/sh

#tshark -r set2.pcap -2 -T fields -R ip -e ip.dst \
#| sort -n | uniq -c | sort -n > sorted-ips.txt

IPS=$(cat sorted-ips.txt | awk '{print $2}')


for i in $IPS; do
        echo $i
done

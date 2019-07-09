#! /bin/sh
# TODO: Abstract script

tshark -r set2.pcap -2 -T fields -R ip -e ip.dst \
| sort -n | uniq -c | sort -n > sorted-ips.txt

# Command tells tshark to read from the set2.pcap file using a
# two-pass analysis (-2) and to format the output into fields.
# "-R ip" tells tshark to apply a filter to isolate IP addresses.
# the -e are to define the fields to be displayed. The results
# are then piped to unix commands that first sort the IPs 
# numerically, remove duplicate rows while prepending a count of
# the duplicates, then to sort the addresses numerically based
# on the number of duplicates. All the results are printed to
# the file "sorted-ips".

# Removes duplicate count and saves to an array of IP addresses
IPS=$(cat sorted-ips.txt | awk '{print $2}')

# Reverse DNS lookup every IP address in the array
for i in $IPS; do
        dig +noall +answer -x $i
done

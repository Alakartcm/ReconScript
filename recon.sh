#!/bin/bash	

# This script is to be used for recon, reporting findings to a messaging service through notify

# Requirements
## Proxychains config. Can remove proxy chains from script if running from VPS.
## OWASP amass
## Project Discovery subfinder, nuclei, & notify
## Tomnomnom anew
## gowitness
## dnsreaper
## OAM tools from OWASP


# Running Amass for subdomains and IP addresses

mkdir -p results/gowitness
mkdir -p output/ipaddress
mkdir -p output/domains
mkdir -p output/httpx
mkdir -p output/masscan
mkdir -p output/dnsreaper

amass enum -df rootdomains.txt 

amass db -df rootdomains.txt -names -ipv4 > amass.txt; cat amass.txt | cut -d " " -f 1 | tee output/domains/amassdomains.txt | cat amass.txt | cut -d " " -f 2 | tee output/ipaddress/ipaddresses.txt


# Workaround command.
#~/go/bin/oam_subs -df rootdomains.txt -names -ipv4 -show > amass.txt; cat amass.txt | cut -d " " -f 1 | tee output/domains/amassdomains.txt | cat amass.txt | cut -d " " -f 2 | tee output/domains/ipaddresses.txt

## Legacy command deprecated in newer version of amass. Will remove.\
## amass db -df rootdomains.txt -names -ipv4 > amass.txt; cat amass.txt | cut -d " " -f 1 | tee amassdomains.txt | cat amass.txt | cut -d " " -f 2 | tee ipaddresses.txt

rm amass.txt

echo "New domains discovered from Amass" | notify -silent | cat output/domains/amassdomains.txt| anew results/subdomains.txt | notify -silent

# cat amassdomains.txt | tee -a subdomains.txt; rm amassdomains.txt 

# Enriching subdomain data with subfinder

cat rootdomains.txt | sudo subfinder | tee output/domains/subfinderdomains.txt

echo "New domains found by subfinder" | notify -silent; cat output/domains/subfinderdomains.txt | anew results/subdomains.txt | notify -silent

find output/domains -type f -exec cat {} + | tee output/domains/temp_subdomains.txt; cat output/domains/temp_subdomains.txt | sort | uniq | tee results/subdomains.txt

############

# Run domains through httpx to find which domains are running a webserver.

cat results/subdomains.txt | httpx-toolkit -fc 500,501,502,503 -sc | tee output/httpx/httpx.txt
cat output/httpx/httpx.txt | grep 200 | cut -d " " -f 1 | tee output/httpx/domains_returning_200.txt
echo "New domains returning 200" | notify -silent; cat output/httpx/domains_returning_200.txt | anew results/domains_returning_200.txt | notify -silent
cat output/httpx/domains_returning_200.txt | tee results/results/domains_returning_200.txt


# Run nuclei and report vulnerabilities.
nuclei -ut 

proxychains nuclei -l output/httpx/httpx.txt -o results/nuclei_output.txt; echo "Vulnerabilities found by Nuclie" | notify -silent; grep -E "low|medium|high|critical" results/nuclei_output.txt | notify -silent

# Port Scan with Proxy Chains

sudo proxychains masscan -iL output/ipaddress/ipaddresses.txt --top-ports 1000 -oX output/masscan/top1000_ports

gowitness nmap -f output/masscan/top1000_ports --open -P results/gowitness/

# Assumes DNS reaper is installed in /opt/dnsreaper
# Use DNSreaper to check for domains vulnerable to a takeover

python3 /opt/dnsreaper/main.py file --filename results/subdomains.txt --parallelism 150 --out stdout > results/potential_takeovers.txt
echo "Domain with potential takeover vulnerabilties" | notify -silent; cat results/potential_takeovers.txt | notify -silent





# Remove Redundant subdomains
# mv subdomains.txt subdomains.txt.old; cat subdomains.txt.old | sort -u | tee subdomains.txt; rm subdomains.txt.old




#!/bin/bash	

# This script is to be used for recon, reporting findings to a messaging service through notify

# Requirements
## Proxychains config. Can remove proxy chains from script if running from VPS.
## OWASP amass
## Project Discovery subfinder, nuclei, & notify
## Tomnomnom anew
## gowitness
## OAM tools from OWASP


# Running Amass for subdomains and IP addresses

amass enum -df rootdomains.txt 

~/go/bin/oam_subs -df rootdomains.txt -names -ipv4 -show > amass.txt; cat amass.txt | cut -d " " -f 1 | tee amassdomains.txt | cat amass.txt | cut -d " " -f 2 | tee ipaddresses.txt

## Legacy command deprecated in newer version of amass. Will remove.\
## amass db -df rootdomains.txt -names -ipv4 > amass.txt; cat amass.txt | cut -d " " -f 1 | tee amassdomains.txt | cat amass.txt | cut -d " " -f 2 | tee ipaddresses.txt

rm amass.txt

echo "New domains discovered from Amass" | notify -silent | cat amassdomains.txt| anew subdomains.txt | notify -silent

cat amassdomains.txt | tee -a subdomains.txt; rm amassdomains.txt 

# Enriching subdomain data with subfinder

cat rootdomains.txt | sudo subfinder | tee subfinderdomains.txt

echo "New domains found by subfinder" | notify -silent; cat subfinderdomains.txt | anew subdomains.txt | notify -silent; rm subfinderdomains.txt

# Run domains through httpx to find which domains are running a webserver.

cat subdomains.txt | httpx-toolkit -sc | tee httpx.txt

# Run nuclei and report vulnerabilities.

proxychains nuclei -l httpx.txt -o nuclei_output.txt; grep -E "low|medium|high|critical" nuclei_output.txt | notify -silent

sudo proxychains masscan -iL ipaddresses.txt --top-ports 1000 -oX top1000_ports

gowitness nmap -f top1000_ports --open    


# Remove Redundant subdomains
 mv subdomains.txt subdomains.txt.old; cat subdomains.txt.old | sort -u | tee subdomains.txt; rm subdomains.txt.old




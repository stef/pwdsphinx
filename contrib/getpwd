#!/bin/sh

prompt=${1:-sphinx}
echo -en "SETTITLE sphinx password prompt\nSETPROMPT ${prompt} password\nGETPIN\n" | pinentry | grep '^D' | cut -c3- | tr -d '\n' 

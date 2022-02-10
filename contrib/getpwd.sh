#!/bin/sh

echo -en 'SETTITLE sphinx password prompt\nSETPROMPT sphinx password\nGETPIN\n' | pinentry | grep '^D' | cut -c3- | tr -d '\n' 

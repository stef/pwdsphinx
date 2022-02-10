#!/usr/bin/env sh

# depends on xinput

# get the name of your mouse by running
# xinput --list --short
MOUSEDEV='TPPS/2 IBM TrackPoint'

MOUSEID=$(xinput --list --short | fgrep "$MOUSEDEV" | sed 's/.*id=\([0-9]*\).*/\1/')
THIS=$$
# wait until left mouse click
exec 2>/dev/null
xinput --test-xi2 --root $MOUSEID | while true; do
   read -t 1 line
   case "$line" in
      EVENT\ type\ 16\ \(RawButtonRelease\)) 
         read -t 1 line
         read -t 1 details;
         case "$details" in
            detail:\ 1) pkill -P $THIS xinput ; exit ;;
         esac
         ;;
   esac
done
eval "${@}" ;

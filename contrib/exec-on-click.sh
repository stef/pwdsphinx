#!/usr/bin/env sh

# depends on xinput

# get the name of your mouse by running
# xinput --list --short
[[ -f /etc/sphinx/mousedev ]] && . /etc/sphinx/mousedev 2>/dev/null
[[ -f ~/.config/sphinx/mousedev ]] && . ~/.config/sphinx/mousedev 2>/dev/null
[[ -f ${0%%/*}/mousedev ]]&& . ${0%%/*}/mousedev 2>/dev/null

[[ -z "$MOUSEDEV" ]] && {
    echo "unconfigured mouse device in ${0##*/}, please run 'xinput --list --short | fgrep pointer'"
    echo "select the name of your mouse device, and then set it by running:"
    echo "echo MOUSEDEV='the name of your mouse device' >$config_file"
    echo "where $config_file is one of /etc/sphinx/mousedev, ~/.config/sphinx/mousedev, or ${0%%/*}/mousedev"
    exit 1
}

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

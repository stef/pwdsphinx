#/usr/bin/env sh

getpwd.sh "$1@$2" | sphinx get "$1" "$2" | exec-on-click.sh xdotool type --clearmodifiers '$(cat)'

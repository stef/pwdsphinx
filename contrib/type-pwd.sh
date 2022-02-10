#/usr/bin/env sh

getpwd.sh | sphinx get "$1" "$2" | exec-on-click.sh xdotool type --clearmodifiers '$(cat)'

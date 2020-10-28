#!/usr/bin/env bash

title=" Profile Change "

debug=0


if [ "$debug" -eq 0 ]; then
    logger="logger -t $(basename $0)"
else
    if [ -w "/var/log/register.log" ]; then
        logger="tee -a /var/log/register.log"
    else
        logger="tee -a $HOME/.register.log"
    fi
    echo "========== `date` ==========" | $logger >/dev/null
fi


menu_choice=$(dialog --stdout --keep-tite --clear --title "${title}" --menu " Please select this minions' profile:" 0 50 0 1 "Profile 1" 2 "Profile 2" 3 "Profile 3")
case $menu_choice in
    1) profile="profile1" ;;
    2) profile="profile2" ;;
    3) profile="profile3" ;;
    *) exit ;;
esac

set -o pipefail

{
    echo "+ salt-call --local saltutil.kill_all_jobs" | $logger >/dev/null 2>&1
    salt-call --local saltutil.kill_all_jobs 2>&1 | $logger >/dev/null 2>&1
} | dialog --keep-tite --clear --title "${title}" --gauge "\n Stopping all jobs..." 8 50 0

{
    echo "+ salt-call --local state.sls ${profile}.profile" | $logger >/dev/null 2>&1
    salt-call --local state.sls ${profile}.profile 2>&1 | $logger >/dev/null 2>&1
} | dialog --keep-tite --clear --title "${title}" --gauge "\n Changing the profile of this minion..." 8 50 25
if [ $? -ne 0 ]; then
    dialog --keep-tite --clear --title "${title}" --msgbox "\n Failed to change the profile of this minion." 7 50
    exit 1
fi

{
    echo "+ salt-call --local state.sls ${profile}.install" | $logger >/dev/null 2>&1
    salt-call --local state.sls ${profile}.install 2>&1 | $logger >/dev/null 2>&1
} | dialog --keep-tite --clear --title "${title}" --gauge "\n Installing profile on this minion..." 8 50 50
if [ $? -ne 0 ]; then
    dialog --keep-tite --clear --title "${title}" --msgbox "\n Failed to install profile on this minion." 7 50
    exit 1
fi

{
    echo "+ salt-call --local state.sls bootstrapping.register" | $logger >/dev/null 2>&1
    salt-call --local state.sls bootstrapping.register 2>&1 | $logger >/dev/null 2>&1
    sleep 5
} | dialog --keep-tite --clear --title "${title}" --gauge "\n Registering minion on the master..." 8 50 75

{
    seconds=10
    while [ $seconds -gt 0 ]; do
        percent=$(( 100 - $seconds * 100 / 10 ))
        if [ $seconds -eq 1 ]; then
            echo -e "XXX\n${percent}\n\n Installation finished.\n Rebooting in $seconds second...\nXXX"
        else
            echo -e "XXX\n${percent}\n\n Installation finished.\n Rebooting in $seconds seconds...\nXXX"
        fi
        seconds=$(( $seconds - 1 ))
        sleep 1
    done
} | dialog --keep-tite --clear --title "${title}" --gauge "\n Installation finished.\n Rebooting in 10 seconds..." 9 50 0

set +o pipefail
reboot
exit 0

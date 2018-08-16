#!/usr/bin/env bash
check_os() {
    if [ ! $(lsb_release -si) == "Ubuntu"  ]; then
        echo Currently this script is only supported on Ubuntu.
        exit -1
    else
        echo [+] Ubuntu
    fi
}

# For later use to allow OS beside Ubuntu
check_installer() {
    declare -A osInfo;
    osInfo[/etc/redhat-release]=yum
    osInfo[/etc/arch-release]=pacman
    osInfo[/etc/gentoo-release]=emerge
    osInfo[/etc/SuSE-release]=zypp
    osInfo[/etc/debian_version]=apt-get

    for f in ${!osInfo[@]}
    do
        if [[ -f $f ]];then
            echo "${osInfo[$f]}"
        fi
    done
}
check_cwd() {
    pwd=$(pwd | grep Cortex-Analyzers/utils)
    if [ $? -ne "0" ]; then
        echo "[-] Please run this script in the utils directory."
        exit -1
    else
        echo "[+] Right directory $(pwd | grep 'utils')"
    fi
}

install_dependencies() {
    echo "[ ] Installing dependencies using sudo (libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git)."
    sudo apt-get install libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git
}

remove_dependencies() {
    echo "[ ] Should the above installed dependencies get removed?"
    echo "    This deletes libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev"
    read -p "[y/N]" choice
    if [ "${choice}" == "y" ] || [ "${choice}" == "Y" ]; then
        sudo apt-get purge libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev
    fi
}

cleanup() {
    rm -rf manalyze-master
}

clone_repository() {
    echo "[ ] Cloning repository"
    git clone https://github.com/JusticeRage/Manalyze manalyze-master
}

compile_manalyze() {
    cd manalyze-master
    cmake .
    make
    cd ..
    mkdir -p manalyze/bin
    cp -R manalyze-master/bin/* manalyze/bin
}

update_clamav_signatures() {
    cd manalyze/bin/yara_rules
    python2 update_clamav_signatures.py
    cd ../../../
}

echo This will download and compile Manalyze and place the binary into utils directory. Press [ENTER] to continue.
read

declare -r installer=$(check_installer)
echo Package Manager is ${installer}

check_os
check_cwd
clone_repository
install_dependencies
compile_manalyze
cleanup
remove_dependencies
update_clamav_signatures

if [ -f manalyze/bin/manalyze ]; then
    echo -e "\e[100m\e[92m[+] Manalyze installation successful.\e[0m"
else
    echo -e "\e[100m\e[91m[-] Manalyze installation not successful. See errors above.\e[0m"
fi
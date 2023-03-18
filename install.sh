#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'


check_system(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release='centos'
        systemPackage='yum'
    elif grep -Eqi 'debian|raspbian' /etc/issue; then
        release='debian'
        systemPackage='apt'
    elif grep -Eqi 'ubuntu' /etc/issue; then
        release='ubuntu'
        systemPackage='apt'
    elif grep -Eqi 'centos|red hat|redhat' /etc/issue; then
        release='centos'
        systemPackage='yum'
    elif grep -Eqi 'debian|raspbian' /proc/version; then
        release='debian'
        systemPackage='apt'
    elif grep -Eqi 'ubuntu' /proc/version; then
        release='ubuntu'
        systemPackage='apt'
    elif grep -Eqi 'centos|red hat|redhat' /proc/version; then
        release='centos'
        systemPackage='yum'
    fi

    if [[ "${checkType}" == 'sysRelease' ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == 'packageManager' ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

if check_system packageManager yum; then
sudo -s <<HERE
    yum -y update
    yum -y install python3  || echo -e "[${red}Error:${plain}] Failed to install python3"
    yum -y install python3-pip || echo -e "[${red}Error:${plain}] Failed to install python3-pip"
    yum -y install python3-dev  || echo -e "[${red}Error:${plain}] Failed to install python3-dev"
    yum -y install libssl-dev  || echo -e "[${red}Error:${plain}] Failed to install libssl-dev"
    yum -y install libffi-dev  || echo -e "[${red}Error:${plain}] Failed to install libffi-dev"
    yum -y install build-essential  || echo -e "[${red}Error:${plain}] Failed to install build-essential"
HERE
elif check_system packageManager apt; then
sudo -s <<HERE
    apt-get -y update
    apt-get -y install python3  || echo -e "[${red}Error:${plain}] Failed to install python3"
    apt-get -y install python3-pip || echo -e "[${red}Error:${plain}] Failed to install python3-pip"
    apt-get -y install python3-dev  || echo -e "[${red}Error:${plain}] Failed to install python3-dev"
    apt-get -y install libssl-dev  || echo -e "[${red}Error:${plain}] Failed to install libssl-dev"
    apt-get -y install libffi-dev  || echo -e "[${red}Error:${plain}] Failed to install libffi-dev"
    apt-get -y install build-essential  || echo -e "[${red}Error:${plain}] Failed to install build-essential"
HERE
fi

python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
pip3 install claripy
pip3 install angr
pip3 install re
pip3 install capstone
pip3 install numpy

echo "The installation is complete."
#!/bin/bash

echo "Getting sys_call_table address..."
if [ -f sct_address.h ]; then
    echo "Contents of header previous version (to be removed):";
    cat sct_address.h;
    rm sct_address.h;
fi

RUNNING_KERNEL_VERSION=$(uname -r)
echo "You are running on ${RUNNING_KERNEL_VERSION} kernel"
echo "Parsing System.map..."
SYS_CALL_TABLE_ADDRESS=`grep sys_call_table /boot/System.map-${RUNNING_KERNEL_VERSION} | cut -d" " -f1`

echo "#define SYS_CALL_TABLE_HARD_ADDRESS 0x${SYS_CALL_TABLE_ADDRESS}" > sct_address.h

if [ ! -f sct_address.h ]; then
    echo "Error: could not create sct_address.h. Exiting...";
    exit 1;
fi

echo "Contents of header current version:";
cat sct_address.h;


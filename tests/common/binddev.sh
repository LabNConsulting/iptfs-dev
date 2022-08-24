#!/bin/bash

modprobe vfio-pci

if (( $# < 2 )); then
    echo "usage: mapdev.sh restorescript PCIDEV [PCIDEV ...]"
    exit 1
fi

restore_script=$1; shift

echo -n > ${restore_script}
for pcidev in $*; do
    echo "Working on ${pcidev}"
    declare _devcode=$(lspci -n -s ${pcidev} | cut -d\  -f3)
    MANUF=${_devcode%%:*}
    DEVID=${_devcode##*:}
    echo "MANUF:DEVID = $MANUF:$DEVID"

    if [[ -e /sys/bus/pci/devices/${pcidev}/driver ]]; then
        DRIVER=$(basename $(readlink /sys/bus/pci/devices/${pcidev}/driver))
        if [[ $DRIVER != vfio-pci && -e /sys/bus/pci/drivers/$DRIVER/${pcidev} ]]; then
            echo "Unbinding ${pcidev} from $DRIVER"
            echo ${pcidev} > /sys/bus/pci/drivers/$DRIVER/unbind
            printf 'echo %s > %s\n' "${pcidev}" "/sys/bus/pci/drivers/vfio-pci/unbind" >> ${restore_script}
            printf 'echo %s > %s\n' "${pcidev}" "/sys/bus/pci/drivers/$DRIVER/bind" >> ${restore_script}
        fi
    fi
    if [[ -n $MANUF ]] && [[ -n $DEVID ]]; then
        if [[ ! -e "/sys/bus/pci/drivers/vfio-pci/${pcidev}" ]]; then
            echo "Trying vfio-pci new_id for $MANUF:$DEVID"
            if ! echo "$MANUF $DEVID" > /sys/bus/pci/drivers/vfio-pci/new_id 2> /dev/null; then
                echo "new_id for vfio-pci failed"
            fi
            if [[ ! -e "/sys/bus/pci/drivers/vfio-pci/${pcidev}" ]]; then
                echo "Binding ${pcidev} to vfio-pci"
                if ! echo ${pcidev} > /sys/bus/pci/drivers/vfio-pci/bind; then
                    echo "Binding ${pcidev} to vfio-pci failed"
                fi
            fi
        fi
    else
        echo "Couldn't determine Manufacturer and Device ID for ${pcidev}"
    fi
    if [[ ! -e "/sys/bus/pci/drivers/vfio-pci/${pcidev}" ]]; then
        echo "${pcidev} not present under vfio-pci, exiting"
        exit 1
    fi
done

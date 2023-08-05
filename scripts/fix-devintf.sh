DEVS=$(ip -o link show | egrep 'dev[0-9].*altname' | sed -e '/.*altname .*/s/.*\(dev[0-9]*\):.*altname \(.*\)/\1:\2/')

for dev in $DEVS; do
    dname=${dev%:*}
    rname=${dev#dev*:}
    echo $dname $rname
    echo "Renaming ${dname} to ${rname}"
    sudo ip link property del dev $dname altname $rname
    sudo ip link set $dname name $rname
done


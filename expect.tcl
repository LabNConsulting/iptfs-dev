spawn sudo socat - unix-connect:/tmp/unet-root/r1/s/console

send_user "Sending CR"
send "\r"
send_user "Sent CR, Expecting"

set prompt "\(XXPROMPTXX\|^\[^#\$\]*\(\$\|\#\) \)"

expect {
    "ogin:" {
        send "root\r"
        exp_continue
    } eof {
        send_user "got eof!"
        exit
    } timeout {
        send_user "got timeout!"
        exit
    } -re $prompt
}
send "ls -l /\n"
expect -re $prompt
send_user "done\n"

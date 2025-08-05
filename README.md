Follow these steps:
- In bench (e.g. ARTIST8 board) create following script `testsocat.sh`
    ```json
    #!/bin/bash
    killall -9 socat
    sleep 3
    socat -d -d pty,raw,echo=0,link=/dev/ttyTest,b115200 tcp-listen:12345 &
    chown -R root:art_bt /dev/pts/1
    chmod 777 /dev/pts/1
    chown -R root:art_bt /dev/ttyTest
    chmod 777 /dev/ttyTest
    #chown -R root:art_bt /dev/pts/3
    #chmod 777 /dev/pts/3
    #chown -R root:art_bt /dev/ttyTest
    #chmod 777 /dev/ttyTest
    ```
- In bench run `testsocat.sh`
- In Host PC run this .py script
- In bench (in another terminal) run `systemctl restart bluetoothmanager.service`






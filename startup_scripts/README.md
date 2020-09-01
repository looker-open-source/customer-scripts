# Startup Scripts

Publicly available scripts for on-premise hosted Looker customer startup.

* looker: Startup script for looker running under Java 1.8.  Should be in the /home/looker/looker directory with the looker.jar file, and it should be named looker. The full path to the file will commonly be /home/looker/looker/looker. Use this script for all current versions of Looker.
* looker11: Startup script for looker running with OpenJDK11.  Should be in the /home/looker/looker directory with the looker.jar file, and it *should be named looker*. The full path to the file will commonly be /home/looker/looker/looker. OpenJDK11 is supported starting with Looker version 7.16.  Several things depend on this script being renamed from looker11->looker, so make sure to do this.
* looker_init: Ubuntu init file to start Looker automatically on boot.  This may need some customization depending on user/directory for Looker.  This will also need to be modified to work with RedHat-based Linux distributions.
* looker_mac: A version of the startup script customized for OSX. May require customization.
* monitrc: Very basic sample monitrc to manage the Looker process. 


### To set Looker to start on boot for an Ubuntu host:

#### 16.04 LTS and later
16.04 LTS and later use `systemd` to manage services. Please follow the instructions in [systemd](systemd).

#### For versions before 16.04 LTS
* Download a copy of looker_init to your Looker server.
* As root, save looker_init to /etc/init.d/looker
* As root, edit /etc/init.d/looker. Near the top of the script, change the values of LOOKERDIR and LOOKERUSER if you are using a non-default location or user. 
* As root run ```chmod a+x /etc/init.d/looker```
* As root run ```update-rc.d looker defaults```


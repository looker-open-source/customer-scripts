# Startup Scripts

Publicly available scripts for on-premise hosted Looker customer startup.

* looker_java1.7: Startup script for looker running under Java 1.7.  Should be in the /home/looker/looker directory with the looker.jar file. Please note that all current versions of Looker require Java 1.8 so this script is included for historic reasons.
* looker_java1.8: Startup script for looker running under Java 1.8.  Should be in the /home/looker/looker directory with the looker.jar file, and it should be named looker. The full path to the file will commonly be /home/looker/looker/looker. Use this script for all current versions of Looker.
* looker_init: Ubuntu init file to start Looker automatically on boot.  This may need some customization depending on user/directory for Looker.  This will also need to be modified to work with RedHat-based Linux distributions.
* looker_mac: A version of the startup script customized for OSX. May require customization.
* monitrc: Very basic sample monitrc to manage the Looker process. 


### To set Looker to start on boot for an Ubuntu host:

* Download a copy of looker_init to your Looker server.
* As root, save looker_init to /etc/init.d/looker
* As root, edit /etc/init.d/looker. Near the top of the script, change the values of LOOKERDIR and LOOKERUSER if you are using a non-default location or user. 
* As root run ```chmod a+x /etc/init.d/looker```
* As root run ```update-rc.d looker defaults```


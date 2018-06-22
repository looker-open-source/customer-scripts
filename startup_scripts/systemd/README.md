Systemd replaces the SysV init system. It is used with RHEL 7, CentOS 7, and others.

The instructions on this page were tested on an AWS host running CentOS 7.  

## Enabling Looker to start on boot
To enable Looker to start on boot for a host which uses systemd, perform the following steps as root:

First, save the [looker.service](https://raw.githubusercontent.com/looker/customer-scripts/master/startup_scripts/systemd/looker.service) file from this repository as /etc/systemd/system/looker.service

You may need to customize the looker.service file if you are using a user other than "looker", or if
Looker is not installed in /home/looker/looker.

Second, adjust the file permissions:

```
chmod 664 /etc/systemd/system/looker.service
```

Force Looker to run in the foreground:

In either the /home/looker/looker/looker startup script or in /home/looker/looker/lookerstart.cfg, a file you would need to create, set the --no-daemonize flag in the LOOKERARGS environment variable

```
LOOKERARGS="--no-daemonize"
```
or, if you are running a cluster, or have other custom args, something like
```
LOOKERARGS="--no-daemonize -d looker-db.yml --clustered -H 10.10.10.10 --shared-storage-dir	/path/to/mounted/shared/storage"
```

The --no-daemonize flag is also useful if you plan on using supervisord to manage looker,
but make sure you uncomment out the "trap" command in looker's startup script.

Lastly, run the following commmands:

```
systemctl daemon-reload
systemctl enable looker.service
```

## Managing Looker

To start the service:
```
systemctl start looker
```
Please note that it takes a couple of minutes for Looker to start. If you have a large HyperSQL database
(see the files in the looker/.db directory) startup can take considerably longer. If so you may need to
adjust the TimeoutStartSec setting in the looker.service file.

To stop the service:
```
systemctl stop looker
```

To see the current status
```
systemctl status looker
```

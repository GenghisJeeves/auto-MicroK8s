# auto-MicroK8s
An Ubuntu Core based installation that will automatically set up a local MicroK8s cluster with optional cloud backup

The aim is to be able to build an Ubuntu Core based Raspberry Pi.
The Pi should be able to easily find other devices and set up a cluster.
There is a web interface that listens on HTTP port 8800.
The web interface allows for local configuration of the cluster and adding trusted nodes.

Currently the project is not yet working.
It is likely that the repository will be organised into several separate repositories in the future.
There are some parts that do work.
Currently I am testing with Multipass with a standard Ubuntu server.
The node discovery works and it can install microk8s.
Currently the clustering is not working as the messaging between the two nodes is not working.  
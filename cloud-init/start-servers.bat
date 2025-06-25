rem This script is used to start the servers for the Auto MicroK8s Cluster.
rem It assumes that Multipass is installed and configured on the system.

multipass set local.privileged-mounts=true
cd ..
multipass launch --name aw6-server1 --cpus 1 --memory 2G --disk 8G --cloud-init %cd%\cloud-init\server1.yaml --mount %cd%\snaps\auto-microk8s-cluster:/mnt


# because https://github.com/kubernetes/minikube/issues/1568
minikube stop \
  && minikube start \
    --vm-driver=virtualbox \
    --memory=4096 \
    --addons=ingress \
    --extra-config=apiserver.enable-admission-plugins=PodSecurityPolicy \
  && minikube ssh sudo ip link set docker0 promisc on


# Example of more resources
# --disk-size=50g
# --cpus=4

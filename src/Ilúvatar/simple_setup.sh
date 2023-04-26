#!/bin/sh

# sudo apt-get update -y
# sudo apt-get install -y curl runc bridge-utils iptables net-tools sysstat containerd jq

if ! [ -x "$(command -v go)" ];
then
  echo "go not be found, installing"
  ARCH=amd64
  GO_VERSION=1.18.3
  tar="go${GO_VERSION}.linux-${ARCH}.tar.gz"

  wget https://go.dev/dl/${tar}
  sudo rm -rf /usr/local/go/
  sudo tar -C /usr/local -xzf ${tar}
  rm ${tar}
  export PATH=$PATH:/usr/local/go/bin
fi

go install github.com/containernetworking/cni/cnitool@latest
gopth=$(go env GOPATH)
sudo mkdir -p /opt/cni/bin
sudo mv ${gopth}/bin/cnitool /opt/cni/bin

ARCH=amd64
CNI_VERSION=v1.1.1

curl -sSL https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz | sudo tar -xz -C /opt/cni/bin

sudo /sbin/sysctl -w net.ipv4.conf.all.forwarding=1
echo "net.ipv4.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf

name=$(ip route get 8.8.8.8 | awk '{ print $5; exit }')

local_json="./ilúvatar_worker/src/worker.test.json"
cp ./ilúvatar_worker/src/worker.json $local_json
jq ".networking.hardware_interface = \"$name\"" $local_json > tmp.json && mv tmp.json $local_json
jq ".container_resources.snapshotter = \"overlayfs\"" $local_json > tmp.json && mv tmp.json $local_json

make
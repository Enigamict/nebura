sudo ip netns add host1
sudo ip netns exec host1 ip link set lo up
sudo ip link add name veth1 type veth peer name host1-veth1
sudo ip link set host1-veth1 netns host1
sudo ip addr add 10.0.0.1/24 dev veth1
sudo ip link set veth1 up
sudo ip netns exec host1 ip addr add 10.0.0.2/24 dev host1-veth1
sudo ip netns exec host1 ip link set host1-veth1 up
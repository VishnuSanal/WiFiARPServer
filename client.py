import psutil
from scapy.all import ARP, Ether, sendp
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.packet import Padding

import constants


def send_request(admission_number, interface="wlo1"):
    # target_ip = "192.168.1.1"
    target_ip = get_if_addr(interface)  # FIXME: add the connection server's IP

    kv_data = {constants.key_request: "True", constants.key_adm_no_extra: admission_number}

    extra_data = "&".join(f"{key}={value}" for key, value in kv_data.items()).encode()

    arp_reply = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(interface)) /
            ARP(op=2, psrc=get_if_addr(interface), hwsrc=get_if_hwaddr(interface), pdst=target_ip,
                hwdst="00:00:00:00:00:00") /
            Padding(load=extra_data)
    )

    # print(f"Request sent")

    sendp(arp_reply, iface=interface, verbose=1)


def get_active_nic_list():
    """
    Returns the names of the currently active NIC based on sent/received traffic.
    """
    nic_list = []
    try:
        net_stats = psutil.net_if_stats()
        net_io_counters = psutil.net_io_counters(pernic=True)

        for nic, stats in net_stats.items():
            if stats.isup:
                io_counters = net_io_counters.get(nic)
                if io_counters and (io_counters.bytes_sent > 0 or io_counters.bytes_recv > 0):
                    nic_list.append(nic)
    except Exception:
        pass

    return nic_list


if __name__ == "__main__":
    admn_no = input("Enter your admission number: ")

    # hack! couldn't figure out a reliable way to get the active wireless interface (without using assumptions like w*)
    for nic in get_active_nic_list():
        try:
            send_request(admn_no, nic)
        except Exception:
            pass

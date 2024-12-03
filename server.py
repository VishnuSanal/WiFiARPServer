import re
import subprocess

import redis
from scapy.all import sniff, ARP
from scapy.packet import Padding

import constants
import email_utils

redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)


def send_email(admission_number, target_mac):
    print(f"Sending confirmation email to {admission_number} for the device {target_mac}")

    email_utils.send_approval_link(redis_client, admission_number, target_mac)
    #
    # print("debug: limited access")


def is_desktop_os(ip):
    """
    Determine if the OS of the device at the given IP is a desktop/server OS
    (Windows, Linux, macOS) or a smartphone OS (Android, iOS).
    Returns:
        True if the OS is Windows, Linux, or macOS.
        False if the OS is Android or iOS.
    """
    try:
        result = subprocess.run(['nmap', '-O', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout

        if "OS details" in output:
            os_details = output.split("OS details:")[1].split("\n")[0].strip()
            if re.search(r'Windows|Linux|macOS|Darwin', os_details, re.IGNORECASE):
                return True
            elif re.search(r'Android|iOS', os_details, re.IGNORECASE):
                return False

        if "No exact OS matches" in output:
            return False

    except Exception as e:
        print(f"Error: {e}")

    return False


def process_arp_packet(packet):
    # print(packet.show())

    # if packet.haslayer(ARP):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        if packet.haslayer(Padding):
            raw_data = packet[Padding].load
            try:
                kv_pairs = dict(item.split("=") for item in raw_data.decode().split("&"))
                if constants.key_request in kv_pairs.keys():
                    admission_number = kv_pairs.get(constants.key_adm_no_extra)
                    target_mac = packet[ARP].hwsrc

                    if is_desktop_os(packet[ARP].psrc):
                        print("Target OS verified")
                        send_email(admission_number, target_mac)
            except Exception:
                pass


def arp_sniffer(interface):
    sniff(iface=interface, filter="arp", prn=process_arp_packet, store=0)


if __name__ == "__main__":
    arp_sniffer(interface="wlo1")

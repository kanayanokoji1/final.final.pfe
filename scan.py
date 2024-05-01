import csv
from scapy.all import *
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, KFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve
import os
import seaborn as sns
import matplotlib.pyplot as plt
from termcolor import colored
import pickle
from datetime import datetime
 
def banner():
    """Prints a blue banner with author information."""

    blue_color = 'blue'  # Define the desired blue color
    red_color = 'red'
    print(colored("""


███╗   ██╗██╗██████╗ ███████╗           ███╗   ███╗██╗     
████╗  ██║██║██╔══██╗██╔════╝           ████╗ ████║██║     
██╔██╗ ██║██║██║  ██║███████╗           ██╔████╔██║██║     
██║╚██╗██║██║██║  ██║╚════██║           ██║╚██╔╝██║██║     
██║ ╚████║██║██████╔╝███████║    ██╗    ██║ ╚═╝ ██║███████╗
╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝    ╚═╝    ╚═╝     ╚═╝╚══════╝
                                                            V 0.9
                                                           
                                                   
 NIDS with Machine Learning Model for Attack Detection like DDoS and Dos\n  most run as RooT for scaning and traing AI and testing """, blue_color))

    print(colored("""                                           by Mohamed amine bououd \n                                             Cybersecurity student""", red_color))  # Indented with the rest


def clear_screen():
    os.system("clear")  # Clear the screen

# Define the CSV file name




csv_file = "scan-rapport.csv"
attack_details = []

def detect_ddos(packet):
    """
    Detects and logs details of a DDoS attack.

    Args:
        packet (scapy.Packet): The captured packet.

    Returns:
        None
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # Extract relevant fields from the packet
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        protocol = packet[IP].proto
        syn_count = packet[TCP].flags.S
        syn_ack_count = packet[TCP].flags.SA
        packet_size = len(packet)
        timestamp = packet.time

        # Create a dictionary to store the attack details
        attack_detail = {
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "syn_count": syn_count,
            "syn_ack_count": syn_ack_count,
            "packet_size": packet_size,
            "timestamp": timestamp,
            "flow_id": f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}",
            "fwd_pkt_len_mean": packet_size,
            "fwd_seg_size_avg": packet_size,
            "init_fwd_win_byts": -1,  # Placeholder for now
            "init_bwd_win_byts": 32768,  # Placeholder for now
            "fwd_seg_size_min": 0
        }

        # Append the attack detail to the list
        attack_details.append(attack_detail)

def save_to_csv():
    """
    Saves the attack details to a CSV file.

    Returns:
        None
    """
    # Open the CSV file in write mode
    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)

        # Write the header row
        writer.writerow(["Flow ID", "Timestamp", "Fwd Pkt Len Mean", "Fwd Seg Size Avg",
                         "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Seg Size Min"])

        # Write the attack details
        for attack in attack_details:
            # Convert the timestamp to a human-readable format
            timestamp_str = datetime.fromtimestamp(attack["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")

            writer.writerow([
                attack["flow_id"],
                timestamp_str,
                attack["fwd_pkt_len_mean"],
                attack["fwd_seg_size_avg"],
                attack["init_fwd_win_byts"],
                attack["init_bwd_win_byts"],
                attack["fwd_seg_size_min"]
            ])

def scan_network():
    """
    Scans the network for DDoS attacks and saves the results to a CSV file.

    Returns:
        None
    """
    # Ask the user for the network range
    network_range = input("Enter the network range to scan (e.g., 192.168.0.0/24): ")

    # Ask the user for the scan interval
    scan_interval = int(input("Enter the scan interval in seconds: "))

    # Start scanning the network
    sniff(filter="tcp", prn=detect_ddos, timeout=scan_interval)

    # Save the attack details to the CSV file
    save_to_csv()

    print("Scan completed. The results have been saved to scan-rapport.csv")
    print("1. Scan Network again")
    print("2. Exit")
    choice = input("Enter your choice (1 or 2): ")

    if choice.lower() == '1':
        scan_network()
    else:
        os.system("python main.py")

def main_menu():
  """
  Presents the main menu options to the user.

  Returns:
    None
  """

  clear_screen()
  banner()

  print("1. Scan Network")
  print("2. Exit")

  choice = input("Enter your choice (1 or 2): ").strip()

  if choice == "1":
    scan_network()
    main_menu()  # Recursive call to display menu again
  elif choice == "2":
    os.system("python main.py")
  else:
    print("Invalid choice. Please try again.")
    main_menu()  # Recursive call after invalid choice

# Call the main_menu function to start the program
main_menu()



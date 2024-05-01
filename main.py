import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, KFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve
import os
import seaborn as sns
import matplotlib.pyplot as plt
from termcolor import colored
import pickle

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
                                                   
 NIDS with Machine Learning Model for Attack Detection like DDoS and Dos\n  most run as RooT for scaning and trainf AI and testing """, blue_color))

    print(colored("""                                           by Mohamed amine bououd \n                                             Cybersecurity student""", red_color))  # Indented with the rest


def clear_screen():
    os.system("clear")  
def main():
    clear_screen()
    banner()
    while True:
        print("Please choose an option:")
        print("1. Train AI model")
        print("2. Scan network")
        print("3. Test AI model")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            os.system("python deye9.py")
        elif choice == '2':
            os.system("python scan.py")
        
        elif choice == '3':
            os.system("python ai2test.py")
        elif choice == '4':
            break
        else:
            print(" Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()
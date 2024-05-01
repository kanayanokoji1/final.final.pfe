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
                                                           

                                                   
 NIDS with Machine Learning Model for Attack Detection like DDoS and Dos\n  most run as RooT for scaning and traing AI and testing """, blue_color))

    print(colored("""                                            by Mohamed amine bououd \n                                               Cybersecurity student \n \ntrain AI model with type file CSV file DATASET  \n """, red_color))  # Indented with the rest


def clear_screen():
    os.system("clear")  # Clear the screen

def print_evaluation_metrics(y_test, y_pred):
    """Prints the evaluation metrics in a structured format."""

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')
    red_color = 'red'

    print(colored("Evaluation Metrics:", attrs=["bold"]))
    print("+-----------------+-------+")
    print(colored("| Metric | Score    |", red_color))
    print("+-----------------+-------+")
    print(f"| Accuracy    | {accuracy:.4f} |")
    print(f"| Precision   | {precision:.4f} |")
    print(f"| Recall      | {recall:.4f} |")
    print(f"| F1 Score    | {f1:.4f} |")
    print("+-----------------+-------+")

def get_csv_path():
    """Prompts the user to enter the path to the CSV file and validates the input."""

    while True:
        print("Please enter the CSV file name to train your AI:")
        csv_path = input()
        if os.path.exists(csv_path):
            return csv_path
        else:
            print("Error: File not found. Please enter a valid filename.")

def save_model(model, filename):
    """Saves the trained model to a file."""
    with open(filename, 'wb') as file:
        pickle.dump(model, file)

def main():
    """Executes the main program flow for training, evaluating, visualizing,
    and potentially saving the NIDS model."""

    clear_screen()
    banner()

    try:
        # Get the CSV path from the user
        csv_path = get_csv_path()

        # Load the dataset and preprocess it
        data_columns = ["Fwd Seg Size Min", "Init Bwd Win Byts", "Init Fwd Win Byts",
                        "Fwd Seg Size Min", "Fwd Seg Size Avg", "Label", "Timestamp"]
        data_dtypes = {"Fwd Pkt Len Mean": float, "Fwd Seg Size Avg": float,
                        "Init Fwd Win Byts": int, "Init Bwd Win Byts": int,
                        "Fwd Seg Size Min": int, "Label": str}
        date_col = ["Timestamp"]

        try:
            raw_data = pd.read_csv(csv_path, usecols=data_columns, dtype=data_dtypes,
                                  parse_dates=date_col, index_col=None)
            sorted_data = raw_data.sort_values("Timestamp")
            processed_data = sorted_data.drop(columns=["Timestamp"])
        except pd.errors.ParserError as e:
            print(f"Error parsing CSV: {str(e)}")
            print("Make sure the CSV format is valid and the columns match expectations.")
            return  # Exit the program if parsing fails

        # Split the data into training and testing sets
        X = processed_data.drop(columns=["Label"])
        y = processed_data["Label"]

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Perform K-Fold cross-validation
        kf = KFold(n_splits=5, shuffle=True, random_state=42)

        # Train the RandomForestClassifier
        clf = RandomForestClassifier(n_estimators=45)

        # Evaluate the model using cross-validation
        for train_index, test_index in kf.split(X_train):
            X_train_cv, X_test_cv = X_train.iloc[train_index], X_train.iloc[test_index]
            y_train_cv, y_test_cv = y_train.iloc[train_index], y_train.iloc[test_index]
            clf.fit(X_train_cv, y_train_cv)
            y_pred_cv = clf.predict(X_test_cv)
            print_evaluation_metrics(y_test_cv, y_pred_cv)

        # Make predictions on the test set
        y_pred = clf.predict(X_test)
        y_pred_proba = clf.predict_proba(X_test)

        # Print the evaluation metrics
        print_evaluation_metrics(y_test, y_pred)

        # Plot the confusion matrix (optional, uncomment if desired)
        # plot_confusion_matrix(y_test, y_pred)

        # Plot the ROC curve
        # Optionally save the model (prompt the user for confirmation)
        save_model_choice = input("the model will save as trained_model.pkl Do you want to save the trained model? (y/N): ")
        if save_model_choice.lower() == 'y':
            save_model(clf, "trained_model.pkl")
            print("Model saved successfully!")
        choice = input("back to menu ? (y/n) ")
        if choice.lower() == 'y':
            os.system("python main.py")
        else:
            os.system("python main.py")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

        
if __name__ == "__main__":
    main()

def save_model(model, filename):
    """Saves the trained model to a file."""
    with open(filename, 'wb') as file:
        pickle.dump(model, file)

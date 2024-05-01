import pandas as pd
import joblib
import matplotlib.pyplot as plt
from termcolor import colored
import os

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
                                                   
NIDS with Machine Learning Model for Attack Detection like DDoS and Dos it will generate visualizes confusion matrix classification model performs. 
It details  correctly classified cases (True Positives, True Negatives) 
and misclassified ones (False Positives, False Negatives).save the picture when its done .
""", blue_color))

    print(colored("""                                           by Mohamed amine bououd \n                                              Cybersecurity student\n""", red_color))  # Indented with the rest



 # Print the banner in blue

def clear_screen():
    os.system("clear") 

def preprocess_data(data_path):
    """Preprocesses captured network traffic data.

    Args:
        data_path (str): Path to the CSV file containing the captured data.

    Returns:
        pandas.DataFrame: The preprocessed data if successful, None otherwise.
    """

    data_columns = ["Fwd Seg Size Min", "Init Bwd Win Byts", "Init Fwd Win Byts",
                    "Fwd Seg Size Min", "Fwd Seg Size Avg", "Timestamp"]  # Include 'Timestamp' in usecols
    data_dtypes = {"Fwd Pkt Len Mean": float, "Fwd Seg Size Avg": float,
                    "Init Fwd Win Byts": int, "Init Bwd Win Byts": int,
                    "Fwd Seg Size Min": int}
    date_col = ["Timestamp"]

    try:
        raw_data = pd.read_csv(data_path, usecols=data_columns, dtype=data_dtypes,
                               parse_dates=date_col)
        sorted_data = raw_data.sort_values("Timestamp")
        processed_data = sorted_data.drop(columns=["Timestamp"])
        return processed_data

    except pd.errors.ParserError as e:
        print(f"Error parsing CSV: {str(e)}")
        print("Make sure the CSV format is valid and the columns match expectations.")
        return None  # Exit the program if parsing fails

def predict_labels(model, data):
    """Uses the trained model to make predictions on the captured data."""

    try:
        # Check if the model has a predict_proba method
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(data)
            predictions = model.predict(data)
            return predictions, probabilities
        else:
            predictions = model.predict(data)
            return predictions, None

    except Exception as e:
        print(f"Error making predictions: {str(e)}")
        return None, None

def visualize_predictions(predictions, probabilities):
    """Visualizes the predicted labels and their probabilities."""

    if probabilities is not None:
        plt.scatter(range(len(predictions)), predictions, c=probabilities[:, 1], cmap='bwr')
        plt.colorbar(label='Prediction Probability')
    else:
        plt.scatter(range(len(predictions)), predictions)
    plt.xlabel('Data Point')
    plt.ylabel('Predicted Label')
    plt.title('Predicted Labels with Probabilities')
    plt.show()

def main():
    clear_screen()
    banner()

    # Prompt the user for the paths to the .pkl file and the .csv file
    model_path = input("Enter the trained model (.pkl): ")
    captured_data_path = input("Enter the captured data form the scan(.csv): ")

    try:
        # Load the trained model
        model = joblib.load(model_path)

        # Load and preprocess the captured data
        processed_captured_data = preprocess_data(captured_data_path)

        if processed_captured_data is not None:
            # Make predictions on the captured data
            predictions, probabilities = predict_labels(model, processed_captured_data)

            # Print the predicted labels
            print("Predicted Labels:")
            print(predictions)

            # Visualize the predictions
            visualize_predictions(predictions, probabilities)

    except FileNotFoundError:
        print("Error: Trained model file not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
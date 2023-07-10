from flask import Flask, redirect, request, jsonify, render_template, url_for
from scapy.all import *
import pandas as pd
import time
import csv
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score
import pandas as pd
import numpy as np
import random

app = Flask(__name__)

#http://localhost:8000/

@app.route('/')
def attacks_detection():
    return render_template('landing-page.html')

@app.route('/ddos_mitc_detection', methods=['POST'])
def ddos_mitc_detection():
    
    # Get the inputs from the request
    ip_to_filter = request.form['ip']
    
    # Define the fields we want to extract from each packet
    fields = ['duration', 'source_ip', 'destination_ip', 'syn_bit', 'ack_bit', 'fin_bit', 'packet_size', 'pps', 'sequence_number', 'is_attack']

    # Open the output file for writing
    with open('ddos_mitc_traffic_app_seq_num_300_2_final.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()

        # Define a packet handler function
        def packet_handler(packet):
            global previous_seq_number

            # Only process packets that match the specified IP address
            if IP in packet and packet[IP].src == ip_to_filter or packet[IP].dst == ip_to_filter:
                start_time = time.time()
                packet_size = len(packet)

                time.sleep(random.uniform(0, 0.1))

                sequence_number = packet[IP].seq 

                end_time = time.time()
                duration = end_time - start_time
                pps = packet_size / duration   
                is_attack = 0

                if pps > 1000:
                    if previous_seq_number is not None and sequence_number != previous_seq_number + 1:
                       is_attack = 1

                previous_seq_number = sequence_number
                current_time = time.time()

                if TCP in packet:
                    syn_bit = packet[TCP].flags & 0x02 != 0
                    ack_bit = packet[TCP].flags & 0x10 != 0
                    fin_bit = packet[TCP].flags & 0x01 != 0

                else:
                    syn_bit = 'n/a'
                    ack_bit = 'n/a'
                    fin_bit = 'n/a'

                # Write the fields to the output file
                writer.writerow({
                    'duration': duration,
                    'source_ip': packet[IP].src,
                    'destination_ip': packet[IP].dst,
                    #'protocol': packet[IP].proto,
                    'syn_bit': syn_bit,
                    'ack_bit': ack_bit,
                    'fin_bit': fin_bit,
                    'packet_size': packet_size,
                    'pps': pps,
                    'sequence_number': sequence_number,
                    'is_attack': is_attack,
                })
        previous_seq_number = None
        sniff(filter="ip", prn=packet_handler, timeout=900)
        # 15 minutes - 900 

    # Load the data from the CSV file
    data = pd.read_csv("ddos_mitc_traffic_app_seq_num_300_2_final.csv")

    data = data.drop(['source_ip', 'destination_ip','fin_bit'], axis=1)

    X = data.drop('is_attack', axis=1)
    y = data['is_attack']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Define models
    models = []
    models.append(('Decision Tree', DecisionTreeClassifier()))
    models.append(('SVM', SVC()))
    models.append(('KNN', KNeighborsClassifier()))
    models.append(('Naive Bayes', GaussianNB()))

    # Evaluate each model
    results = []
    names = []
    for name, model in models:
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        results.append(acc)
        names.append(name)

    # Find the model with the highest accuracy
    best_model_idx = results.index(max(results))
    best_model = models[best_model_idx][1]

    ### Make a prediction for a specific timestamp and page ID
    timestamp = 1234567890  # Unix timestamp
    page_id = 123  # Certain pages or resources might be more likely to be targeted by attackers than others.
    num_requests = 1000  # Number of requests
    num_errors = 10  # Number of errors
    duration = 60  # Duration in seconds
    bytes_sent = 1000000  # Some number of bytes sent
    data = np.array([timestamp, page_id, num_requests, num_errors, duration, bytes_sent]).reshape(1, -1)
    is_attack = best_model.predict(data)[0]

##    print("Is attack:", bool(is_attack))
    ## get the percent of the prediction

    if bool(is_attack):
        prediction = "A DDoS or MitC attack is likely to occur on this ip address in the next few minutes."

    else:
        prediction = "A DDoS or MitC attack is not likely to occur on this ip address in the near future."
    
    return redirect(url_for('show_result', prediction=prediction))

@app.route('/detection-result')
def show_result():
    prediction = request.args.get('prediction')
    return render_template('show_result.html', prediction=prediction)

if __name__ == '__main__':
    app.run(host="localhost", port=8000, debug=False)

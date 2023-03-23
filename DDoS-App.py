from flask import Flask, redirect, request, jsonify, render_template, url_for
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
from scapy.all import *
import pandas as pd
import time
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import accuracy_score


app = Flask(__name__)

#http://localhost:8000/

@app.route('/')
def detection():
        return render_template('landing-page.html')

@app.route('/ddos_detection', methods=['POST'])
def ddos_detection():
    # Get the inputs from the request
    
    target_ip = request.form['ip']
    
    # Define the DDoS and MitC detection function
    def detect_attack(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if dst_ip == target_ip and TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
                # kshyre pjesen e mitc edhe niher
                if flags & 2 or flags & 4:
                    # SYN or RST flags set
                    label = "malicious"
                    df = pd.DataFrame([[time.time(), src_ip, dst_ip, src_port, dst_port, flags, label]], columns=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags', 'label'])
                    df.to_csv('ddos_and_mitc_attack.csv', mode='a', index=False, header=not os.path.exists('ddos_and_mitc_attack.csv'))
                elif 'HTTP' in pkt and len(pkt['HTTP'].fields) > 50:
                    # HTTP request with a large number of headers - MITC attack
                    label = "malicious"
                    df = pd.DataFrame([[time.time(), src_ip, dst_ip, src_port, dst_port, len(pkt['HTTP'].fields)]], columns=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'num_headers', 'label'])
                    df.to_csv('ddos_and_mitc_attack.csv', mode='a', index=False, header=not os.path.exists('ddos_and_mitc_attack.csv'))
                else:
                    label = "normal"
                    df = pd.DataFrame([[time.time(), src_ip, dst_ip, src_port, dst_port, flags, label]], columns=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags', 'label'])
                    df.to_csv('ddos_and_mitc_attack.csv', mode='a', index=False, header=not os.path.exists('ddos_and_mitc_attack.csv'))
    
    # Start sniffing packets
    start_time = time.time()
    duration = 20 * 60  # 20 minutes in seconds
    while time.time() - start_time < duration:
            sniff(prn=detect_attack, timeout=10)

##
### Load the data from the CSV file
    df = pd.read_csv('ddos_and_mitc_attack.csv')

        # Define the features and labels
    X = df[['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags']]
    y = df['label']

        # One-hot encode the IP addresses
    ip_encoder = OneHotEncoder(categories='auto', sparse=False, handle_unknown='ignore')
    ip_transformer = ColumnTransformer([('one_hot', ip_encoder, ['src_ip', 'dst_ip', 'flags'])], remainder='passthrough')
    X = ip_transformer.fit_transform(X)

        # Scale the features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

        # Train the SVM model
    model = SVC()
    model.fit(X, y)

        # Make a prediction
    predictions = model.predict(X)
    accuracy = accuracy_score(y, predictions)
    print("Accuracy:", accuracy)
    percent_malicious = sum(predictions == 'malicious') / len(predictions) * 100
    print("Percentage of malicious packets in 20 minutes: {:.2f}%".format(percent_malicious))

    return redirect(url_for('show_result', percent_malicious=percent_malicious))

@app.route('/detection-result')
def show_result():
    percent_malicious = request.args.get('percent_malicious')
    return render_template('show_result.html', percent_malicious=percent_malicious)

if __name__ == '__main__':
    app.run(host="localhost", port=8000, debug=False)

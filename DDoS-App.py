from flask import Flask, request, jsonify, render_template
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
from scapy.all import *
import pandas as pd
import time

app = Flask(__name__)

#http://localhost:8000/ddos_detection

@app.route('/')
def upload_form():
        return render_template('landing-page.html')

@app.route('/ddos_detection', methods=['POST'])
def ddos_detection():
    # Get the inputs from the request
    
    target_ip = request.form['ip']
    file_name = request.form['filename']
    algorithm = request.form['algorithm']
    
    # Define the DDoS and MitC detection function
    def detect_attack(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if dst_ip == target_ip and TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
                if flags & 2 or flags & 4:
                    # SYN or RST flags set
                    df = pd.DataFrame([[time.time(), src_ip, dst_ip, src_port, dst_port, flags]], columns=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags'])
                    df.to_csv(file_name + '.csv', mode='a', index=False, header=not os.path.exists(file_name + '.csv'))
                elif flags & 16:
                    # ACK flag set
                    df = pd.read_csv(file_name)
                    df = df[df['src_ip'] == src_ip]
                    if len(df) > 0:
                        # Potential MitC attack detected
                        df = pd.DataFrame([[time.time(), src_ip, dst_ip, src_port, dst_port, flags]], columns=['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags'])
                        df.to_csv(file_name + '_mitc.csv', mode='a', index=False, header=not os.path.exists(file_name + '_mitc.csv'))
    
    # Start sniffing packets
    sniff(prn=detect_attack)
    
    # Load the traffic data into a Pandas DataFrame
    df = pd.read_csv(file_name + '.csv')
    
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(df[['timestamp', 'src_ip', 'src_port', 'flags']], df['dst_ip'], test_size=0.3)
    
    # Train a machine learning model based on the chosen algorithm
    if algorithm == 'decision_tree':
        model = DecisionTreeClassifier()
    elif algorithm == 'svm':
        model = SVC()
    elif algorithm == 'naive_bayes':
        model = GaussianNB()
    elif algorithm == 'k_means':
        model = KMeans()
    else:
        print(jsonify({'error': 'Invalid algorithm choice'}))
    
    model.fit(X_train, y_train)
    
    # Make a prediction for a potential DDoS attack
    prediction = model.predict(X_test)
    
    # Load the MitC data into a Pandas DataFrame
    df_mitc = pd.read_csv(file_name + '_mitc.csv')
    
    # Check if there are any potential MitC attacks
    if len(df_mitc) > 0:
        print(jsonify({'prediction': 'MitC attack detected', 'mitc_data': df_mitc.to_dict('records')}))
    else:
        print(jsonify({'prediction': prediction.tolist()}))

if __name__ == '__main__':
    app.run(host="localhost", port=8000, debug=False)

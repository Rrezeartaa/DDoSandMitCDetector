import pandas as pd
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import accuracy_score

# Load the data from the CSV file
df = pd.read_csv('ddos_attack.csv')

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

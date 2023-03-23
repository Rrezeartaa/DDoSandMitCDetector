import pandas as pd
from sklearn.naive_bayes import GaussianNB
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

# Train the Naive Bayes model
model = GaussianNB()
model.fit(X, y)

prediction = model.predict(X)
malicious_percentage = round((sum(prediction == 'malicious') / len(prediction)) * 100, 2)

# Print the results
print("Accuracy:", round(accuracy_score(y, prediction) * 100, 2), "%")
print("Percentage of malicious packets:", malicious_percentage, "%")

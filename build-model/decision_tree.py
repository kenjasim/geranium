import sklearn as tree
import pandas as pd

from sklearn.tree import DecisionTreeClassifier # Import Decision Tree Classifier
from sklearn.model_selection import train_test_split # Import train_test_split function
from sklearn import metrics #Import scikit-learn metrics module for accuracy calculation

from sklearn.tree import export_graphviz
from sklearn.externals.six import StringIO  
from IPython.display import Image  
import pydotplus
from joblib import dump, load

# import the dataset
dataset = pd.read_csv("dataset.csv")
feature_cols = ["tcp_packets", "tcp_source_port", "tcp_destination_port", "tcp_fin_flag", "tcp_syn_flag", "tcp_push_flag", "tcp_ack_flag", "tcp_urgent_flag", "udp_packets", "udp_source_port", "udp_destination_port", "icmp_packets"]
X = dataset[feature_cols]
y = dataset.target

# Split dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2) # 80% training and 20% test

# Create Decision Tree classifer object
clf = DecisionTreeClassifier()
 
# Train Decision Tree Classifer
clf = clf.fit(X_train,y_train)

#Predict the response for test dataset
y_pred = clf.predict(X_test)

# Model Accuracy, how often is the classifier correct?
print("Accuracy: ",metrics.accuracy_score(y_test, y_pred))
print("Precision: ",metrics.precision_score(y_test, y_pred, average=None))
print("Recal: ",metrics.recall_score(y_test, y_pred, average=None))

# Save Decision Tree Model to File to be redeployed
from joblib import dump, load
dump(clf, '../intrusion-detection/IDS.joblib') 

# Visualise Decison tree
dot_data = StringIO()
export_graphviz(clf, out_file=dot_data,  
                filled=True, rounded=True,
                special_characters=True,feature_names = feature_cols,class_names=['normal','synflood','udpflood','finflood','pshackflood'])
graph = pydotplus.graph_from_dot_data(dot_data.getvalue())  
graph.write_png('tree.png')
Image(graph.create_png())
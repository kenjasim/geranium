import sklearn as tree
import pandas as pd

from sklearn.tree import DecisionTreeClassifier # Import Decision Tree Classifier
from sklearn.model_selection import train_test_split # Import train_test_split function
from sklearn import metrics #Import scikit-learn metrics module for accuracy calculation
from sklearn.model_selection import cross_val_score

from sklearn.tree import export_graphviz
from sklearn.externals.six import StringIO  
from IPython.display import Image  
import pydotplus
from joblib import dump, load

class DataModeling():

    def __init__(self, dataset, model_path, image_path):
        # import the dataset
        print("#####################")
        print("#   DATA MODELING   #")
        print("#####################")
        print ('\n')
        print("Reading Datset: " + str(dataset))
        print("--------------------------------------------------------------")

        dataset = pd.read_csv(dataset)
        dataset.columns = ["tcp_packets", "tcp_source_port", "tcp_destination_port", "tcp_fin_flag", "tcp_syn_flag", "tcp_push_flag", "tcp_ack_flag", "tcp_urgent_flag", "udp_packets", "udp_source_port", "udp_destination_port", "icmp_packets", "target"]
        self.feature_cols = ["tcp_packets", "tcp_source_port", "tcp_destination_port", "tcp_fin_flag", "tcp_syn_flag", "tcp_push_flag", "tcp_ack_flag", "tcp_urgent_flag", "udp_packets", "udp_source_port", "udp_destination_port", "icmp_packets"]
        self.X = dataset[self.feature_cols]
        self.y = dataset.target

        # train the tree
        print("Training Model")
        print("--------------------------------------------------------------")
        self.train()

        # Test the tree
        print("Testing Model")
        print("--------------------------------------------------------------")
        self.test()

        # export the tree
        self.model_path = model_path
        self.image_path = image_path
        self.export_tree()

    def train(self):
        # Split dataset into training set and test set
        X_train, self.X_test, y_train, self.y_test = train_test_split(self.X, self.y, test_size=0.2) # 80% training and 20% test

        # Create Decision Tree classifer object
        self.clf = DecisionTreeClassifier()
        
        # Train Decision Tree Classifer
        self.clf = self.clf.fit(X_train,y_train)
    
    def test(self):
        #Predict the response for test dataset
        y_pred = self.clf.predict(self.X_test)

        # Do cross-validation
        scores = cross_val_score(self.clf, self.X, self.y, cv=5)
        print(scores)

        # Model Accuracy, how often is the classifier correct?
        print("Accuracy: ",metrics.accuracy_score(self.y_test, y_pred))
        print("Precision: ",metrics.precision_score(self.y_test, y_pred, average=None))
        print("Recal: ",metrics.recall_score(self.y_test, y_pred, average=None))
        print("--------------------------------------------------------------")
    
    def export_tree(self):
        print("Exporting Model to: " + self.model_path)
        print("--------------------------------------------------------------")
        # Save Decision Tree Model to File to be redeployed
        dump(self.clf, self.model_path) 

        # Visualise Decison tree
        print("Exporting Image to: " + self.model_path)
        print("--------------------------------------------------------------")
        dot_data = StringIO()
        export_graphviz(self.clf, out_file=dot_data,  
                        filled=True, rounded=True,
                        special_characters=True,feature_names = self.feature_cols,class_names=['normal','synflood','udpflood','finflood','pshackflood'])
        graph = pydotplus.graph_from_dot_data(dot_data.getvalue())  
        graph.write_png(self.image_path)
        Image(graph.create_png())








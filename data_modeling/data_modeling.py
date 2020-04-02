import pandas as pd
import numpy as np

from sklearn.tree import DecisionTreeClassifier 
from sklearn.model_selection import train_test_split
from sklearn import metrics 
from sklearn.model_selection import cross_val_score
from sklearn import preprocessing
from sklearn.feature_selection import SelectFromModel

# from sklearn.tree import export_graphviz
# from sklearn.externals.six import StringIO  
# from IPython.display import Image  
# import pydotplus
# from sklearn.linear_model import Ridge
# from sklearn.model_selection import validation_curve
from joblib import dump, load

class DataModeling():
    """ 
    Implimentation of the decision tree classifier 
    from sklearn, the funtion will train a classifer and
    will calculate the accuracy, precision and recall and will
    extract the model.
    """

    def __init__(self, dataset, model_path, classes):
        """ 
        The function run when a decision tree is instantiated, the train 
        and test funnctions are called and the model is then extracted.
        Keyword Arguments
        dataset - the dataset to train the tree
        model_path - place to store the model
        classes - the classes apparent in the dataset
        """
    
        # import the dataset
        print("#####################")
        print("#   DATA MODELING   #")
        print("#####################")
        print("--------------------------------------------------------------")
        print("Reading Datset: " + str(dataset))
        print("--------------------------------------------------------------")

        # Read the dataset into a dataframe
        dataset = pd.read_csv(dataset)
        dataset.columns = ["tcp_packets", "tcp_source_port", "tcp_destination_port", "tcp_fin_flag", "tcp_syn_flag", "tcp_push_flag", "tcp_ack_flag", "tcp_urgent_flag", "udp_packets", "udp_source_port", "udp_destination_port", "icmp_packets", "target"]
        self.feature_cols = ["tcp_packets", "tcp_source_port", "tcp_destination_port", "tcp_fin_flag", "tcp_syn_flag", "tcp_push_flag", "tcp_ack_flag", "tcp_urgent_flag", "udp_packets", "udp_source_port", "udp_destination_port", "icmp_packets"]
        
        # Split into features and target
        self.X = dataset[self.feature_cols]
        self.y = dataset.target

        # Process the target classes to be numerical 
        self.classes = classes
        le = preprocessing.LabelEncoder()
        le.fit(self.classes)
        self.y = le.transform(self.y)

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
        self.export_tree()

    def train(self):
        """ 
        Split the dataset into training data and test data, then the decision tree is trained
        using the training data.
        """

        # Split dataset into training set and test set
        X_train, self.X_test, y_train, self.y_test = train_test_split(self.X, self.y, test_size=0.2) # 80% training and 20% test

        # Create Decision Tree classifer object
        self.clf = DecisionTreeClassifier(max_depth = 5) 
        # Train Decision Tree Classifer
        self.clf = self.clf.fit(X_train,y_train)
    
    def test(self):
        """ 
        Calculate the accuracy, precision, recall of the model and the cross validation
        scores
        """
        #Predict the response for test dataset
        y_pred = self.clf.predict(self.X_test)

        # Do cross-validation
        scores = cross_val_score(self.clf, self.X, self.y, cv=5)
        print(scores)

        # Model Accuracy, how often is the classifier correct?
        print("Accuracy: ",metrics.accuracy_score(self.y_test, y_pred))
        print("Precision: ",metrics.precision_score(self.y_test, y_pred, average='macro'))
        print("Recal: ",metrics.recall_score(self.y_test, y_pred, average='macro'))
        print("--------------------------------------------------------------")
    
    def export_tree(self):
        """ 
        Export the trained decision tree to a joblib file
        """
        print("Exporting Model to: " + self.model_path)
        print("--------------------------------------------------------------")
        # Save Decision Tree Model to File to be redeployed
        dump(self.clf, self.model_path) 

        # Visualise Decison tree
        # print("Exporting Image to: " + self.model_path)
        # print("--------------------------------------------------------------")
        # dot_data = StringIO()
        # export_graphviz(self.clf, out_file=dot_data,  
        #                 filled=True, rounded=True,
        #                 special_characters=True,feature_names = self.feature_cols,class_names=self.classes)
        # graph = pydotplus.graph_from_dot_data(dot_data.getvalue())  
        # graph.write_png("tree.png")
        # Image(graph.create_png())
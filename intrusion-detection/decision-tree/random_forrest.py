import numpy as np
import decision_tree
# *****************************************************************
# Random Forrest Classifier

class RandomForrest():
    """ Impliments the random forrest classifier. It generates n decision trees
        and trains them on bootstraped data
    """

    def __init__(self, dec_num):
        """ The function run when a random forrest is instantiated

        Keyword Arguments
        dec_num - the number of decision trees to train
        """
        self.dec_num = dec_num

    def fit(self, data, targets):
        """ fits the data to n decision trees

        Keyword Arguments
        data - the arrays which describe the pacman scene
        target - the move associated with each array
        """
        self.trees = []

        # Create n decision trees from random sample 
        # of train data
        for _ in range(self.dec_num):
            train, target = self.generate_train(data, targets)
            dt = decision_tree.DecisionTree(train, target)
            self.trees.append(dt)

    def predict(self, data):
        """ returns the class which is most voted for by the decision tree

        Keyword Arguments
        data - The array of features to predict on

        Returns
        prediction - the class which is predicted by the tree
        """
        predictions = []

        # Loop through the decison trees and collate the results
        for tree in self.trees:
            predictions.append(tree.predict(data))
        
        # Return the most numerous value
        prediction = self.find_mode(predictions)
        return prediction

    def generate_train(self, data, targets):
        """ takes the data and creates a bootstraped training set

        Keyword Arguments
        data - the arrays which describe the pacman scene
        target - the move associated with each array

        Returns
        train - The boostraped training data
        target - The relevent target classes
        """
        # Randomly sample the training set
        train_data = list(zip(data, targets))

        # Randomly select the samples of the training data with replace=true to enable
        # bootstraping
        train_data = np.asarray(train_data)
        train_data = train_data[np.random.choice(train_data.shape[0], len(data), replace=True)]

        # Seperate into data and target
        train, target = zip(*train_data)

        return train, target

    def find_mode(self, predictions):
        """ Returns the mode of the class predictions for decision trees

        Keyword Arguments
        predictions - an array of predictions

        Returns
        prediction - The mode class
        """
        # returns the unique values and their counts
        unique_predictions, counts = np.unique(predictions, return_counts = True)

        # Return the maximum count
        return unique_predictions[np.argmax(counts)]
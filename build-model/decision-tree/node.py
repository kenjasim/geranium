import numpy as np

# *****************************************************************
# node class
class node():
    """ Defines a specific node in the decision tree, contains the data
        targets features avalible and the next nodes
    """

    def __init__(self,best_feature, data, target, features_avalible):
        """ The function run when a node is instantiated

        Keyword Arguments
        best_feature - the feature this node has been split on
        data - the arrays which describe the pacman scene
        target - the move associated with each array
        features_avalible - the features which can be split on
        """
        self.best_feature = best_feature
        self.data = data
        self.target = target
        self.features_avalible = features_avalible
        self.next_nodes = {}

    def split(self):
        """ Calculates the best features to split on and returns the 
            feature, the subsets and the targets

        Returns
        best_feature - the best feature to split on
        subsets - the subsets associated with this split
        target - the associated target classes
        """
        #Find the number of samples and the number of features
        data = np.asarray(self.data)

        features_subsets = []
        targets_subsets = []
        ginis = []
        for feat in self.features_avalible:
            # set the unique values that the features can take
            values = [0,1]
            unique_num = np.asarray(values)

            # Calculate the length of the data
            data_len = len(data)

            # Create a list for the gini impunities
            gini = []

            # Create a list to store the subests and targets in
            subsets = []
            target_split = []

            # Split the data into subsets based on the values that 
            # they take
            for num in unique_num:
                subset = []
                target = []
                for index, d in enumerate(data):
                    if d[feat] == num:
                        subset.append(d)
                        target.append(self.target[index])
                subsets.append(subset)
                target_split.append(target)
                gini.append((len(subset)/data_len) * self.gini_impunity(subset, target))
            
            # Calculate the gini value and store it
            gini_value = np.sum(gini)

            # Append the split and target
            features_subsets.append(subsets)
            targets_subsets.append(target_split)
            ginis.append(gini_value)

        return self.features_avalible[np.argmin(ginis)], features_subsets[np.argmin(ginis)], targets_subsets[np.argmin(ginis)]

    def gini_impunity(self, subset, targets):
        """ Calculates the gini impunity of a specific split

        Keyword Arguments
        subset - the subsets of the split
        targets - the corresponding target classes

        Returns
        gini - the gini impunity of the split
        """
        # Loop through each class and calculate the probability
        probabilities = np.zeros(4, dtype=np.float64)
        subset = np.asarray(subset)
        targets = np.array(targets)
        targets.ravel()

        # Find the possible values of classes
        self.classes = np.unique(targets)

        for c in self.classes: 
            subset_c = subset[c == targets]
            # Calculate the probability squared
            if len(subset)==0:
                continue
            probabilities[c] = (subset_c.shape[0] / float(len(subset)))**2
        
        # calculate the gini impunities
        gini = 1 - np.sum(np.asarray(probabilities))
        return gini

    def predict(self, data):
        """ returns the class which the tree classifies to by recursivly
            going through the nodes until the data can be classified

        Keyword Arguments
        data - The array of features to predict on

        Returns
        prediction - the class which is predicted by the tree
        """
        # Extract the feature of intrest from the data
        data_feature = data[self.best_feature]

        # Get the next node based on its value
        next_node = self.next_nodes[data_feature]

        # If its a class return it if not then re run
        if isinstance(next_node, node):
            val = next_node.predict(data)
        else:
            val = next_node
        return val
import numpy as np
import node

# *****************************************************************
# Decision Tree Classifier

class DecisionTree():
    """ Implimentation of the decision tree classifier 
        It takes the data and calcultes the best split,
        and recursivly splits the tree until a classification
        is found. The splits are calculated using the gini
        impunity. The prediction is calcuated by going down the tree
        until it reaches a class
    """

    def __init__(self, data, targets):
        """ The function run when a decision tree is instantiated, the fit 
            function is called here to build the tree.

        Keyword Arguments
        data - the arrays which describe the pacman scene
        target - the move associated with each array
        """
        #Find the number of samples and the number of features
        data = np.asarray(data)
        _, num_features = data.shape
        features = np.arange(num_features)

        # Create the root node
        root_node = node.node(None, data, targets, features)

        # Fit the data to the tree
        self.tree = self.fit(root_node, None)

    def fit(self, curr_node, parent_node):
        """ Generates new nodes by spliting the data recursivly

        Keyword Arguments
        curr_node - The current node of the tree to check
        parent_node - The node above the tree to check
        """
        #Find the number of samples and the number of features
        data = np.asarray(curr_node.data)

        features = curr_node.features_avalible

        # Find the possible values of classes
        targets = curr_node.target
        self.classes = np.unique(targets)

        #If there is no data left then return the parents most likely class
        if len(data) == 0:
            # Get the classes of the parent
            targets = parent_node.target
            # Find the unique classes and the count
            unique_class, counts = np.unique(targets, return_counts = True)
            # Return the most numerous one
            return unique_class[np.argmax(counts)]
        
        #If there is one class left then return that
        elif len(self.classes) == 1:
            return self.classes[0]

        #If there are no features left then return the parent most likely class
        elif len(features) == 0:
            # Get the classes of the parent
            targets = parent_node.target
            # Find the unique classes and the countnode(
            unique_class, counts = np.unique(targets, return_counts = True)
            # Return the most numerous one
            return unique_class[np.argmax(counts)]
        
        else:
            # Split the node based on its features
            best_feature, split, target = curr_node.split()
            # set the current nodes best feature
            curr_node.best_feature = best_feature
            # Check as unable to delete last feature from an np array
            if len(features) == 1:
                features = []
            else:
                features = features[features != best_feature]
            
            # Loop through the subset and the target creating new sub trees
            for s,t in zip(split,target):
                # If there is no data left then pass the relevant nodes based on if the answer
                # would be a 0 or a 1
                if len(s) == 0:
                    if len(curr_node.next_nodes) == 0:
                        new_node = node.node(None, [], [], features)
                        new_tree = self.fit(new_node, curr_node)
                        curr_node.next_nodes.update({0: new_tree})
                    else:
                        new_node = node.node(None, [], [], features)
                        new_tree = self.fit(new_node, curr_node)
                        curr_node.next_nodes.update({1: new_tree})
                else:
                    new_node = node.node(None, s, t, features)
                    new_tree = self.fit(new_node, curr_node)
                    curr_node.next_nodes.update({s[0][best_feature]: new_tree})
        return curr_node

    def predict(self, data):
        """ Generates a prediction from the tree

        Keyword Arguments
        data - The array of features to predict on

        Returns
        prediction - the class which is predicted by the tree
        """
        # Call the predict function on the tree
        prediction = self.tree.predict(data)
        return prediction

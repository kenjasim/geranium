from sklearn.tree import DecisionTreeClassifier 
from sklearn.model_selection import train_test_split
from sklearn import metrics 
from sklearn.model_selection import cross_val_score
from sklearn import preprocessing
from sklearn import datasets


X,y = datasets.fetch_kddcup99(return_X_y=True)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2) # 80% training and 20% test

# Create Decision Tree classifer object
clf = DecisionTreeClassifier()

# Train Decision Tree Classifer
clf = clf.fit(X_train,y_train)

#Predict the response for test dataset
y_pred = clf.predict(X_test)

# Do cross-validation
scores = cross_val_score(clf, X, y, cv=5)
print(scores)

# Model Accuracy, how often is the classifier correct?
print("Accuracy: ",metrics.accuracy_score(y_test, y_pred))
print("Precision: ",metrics.precision_score(y_test, y_pred, average='macro'))
print("Recal: ",metrics.recall_score(y_test, y_pred, average='macro'))
print("--------------------------------------------------------------")

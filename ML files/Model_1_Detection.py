#Libraries

import numpy as np 
import pandas as pd 
import re
import matplotlib.pyplot as plt
import seaborn as sns
from urllib.parse import urlparse
from tld import get_tld
import os.path
import time
import plotly.express as px
import pickle

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix,classification_report,accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC  
from sklearn.naive_bayes import GaussianNB


import warnings
warnings.filterwarnings("ignore")

import logging
logging.basicConfig(filename='log.txt',level=logging.DEBUG, format='%(asctime)s %(message)s')

urldata = pd.read_csv("./Malicious URLs detection.csv")

urldata = urldata.drop('Unnamed: 0',axis=1)
print(urldata.head())

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
    
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1
    
def len_preprocess(url_dataset):
    #Length of URL
    url_dataset['url_length'] = url_dataset['url'].apply(lambda i: len(str(i)))
    
    #Hostname Length
    url_dataset['hostname_length'] = url_dataset['url'].apply(lambda i: len(urlparse(i).netloc))
    
    #Path Length
    url_dataset['path_length'] = url_dataset['url'].apply(lambda i: len(urlparse(i).path))
    
    url_dataset['fd_length'] = url_dataset['url'].apply(lambda i: fd_length(i))
    url_dataset['tld'] = url_dataset['url'].apply(lambda i: get_tld(i,fail_silently=True))
    url_dataset['tld_length'] = url_dataset['tld'].apply(lambda i: tld_length(i))

len_preprocess(urldata)
urldata = urldata.drop("tld",1)
print(urldata.head())

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def count_preprocess(url_dataset):
    url_dataset['count_dir'] = url_dataset['url'].apply(lambda i: no_of_dir(i))
    url_dataset['count-letters']= url_dataset['url'].apply(lambda i: letter_count(i))
    url_dataset['count-digits']= url_dataset['url'].apply(lambda i: digit_count(i))
    url_dataset['count-www'] = url_dataset['url'].apply(lambda i: i.count('www'))
    url_dataset['count-https'] = url_dataset['url'].apply(lambda i : i.count('https'))
    url_dataset['count-http'] = url_dataset['url'].apply(lambda i : i.count('http'))
    url_dataset['count='] = url_dataset['url'].apply(lambda i: i.count('='))
    url_dataset['count.'] = url_dataset['url'].apply(lambda i: i.count('.'))
    url_dataset['count%'] = url_dataset['url'].apply(lambda i: i.count('%'))
    url_dataset['count?'] = url_dataset['url'].apply(lambda i: i.count('?'))
    url_dataset['count@'] = url_dataset['url'].apply(lambda i: i.count('@'))
    url_dataset['count-'] = url_dataset['url'].apply(lambda i: i.count('-'))
    
count_preprocess(urldata)
print(urldata.head())

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return -1
    else:
        # print 'No matching pattern found'
        return 1
    
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return -1
    else:
        return 1

def ip_process(url_dataset):
    url_dataset['short_url'] = url_dataset['url'].apply(lambda i: shortening_service(i))
    url_dataset['use_of_ip'] = url_dataset['url'].apply(lambda i: having_ip_address(i))

ip_process(urldata)


#Predictor Variables

x = urldata[['hostname_length',
       'path_length', 'fd_length', 'tld_length', 'count-', 'count@', 'count?',
       'count%', 'count.', 'count=', 'count-http','count-https', 'count-www', 'count-digits',
       'count-letters', 'count_dir', 'use_of_ip']]


y = urldata['result']

x_train, x_test, y_train, y_test = train_test_split(x, y, train_size=0.3, random_state=42)


log_reg_model = LogisticRegression()
log_reg_model.fit(x_train,y_train)

log_reg_predictions = log_reg_model.predict(x_test)


print(accuracy_score(y_test, log_reg_predictions), "\n\n\n")

print('Training Accuracy :',log_reg_model.score(x_train,y_train))
print('Testing Accuracy :',log_reg_model.score(x_test,y_test))

con_mat = pd.DataFrame(confusion_matrix(log_reg_model.predict(x_test), y_test),
            columns = ['Predicted:Bad', 'Predicted:Good'],
            index = ['Actual:Bad', 'Actual:Good'])


print('\nCLASSIFICATION REPORT\n')
print(classification_report(log_reg_model.predict(x_test), y_test,
                            target_names =['Bad','Good']))

model_accuracy = {}
print('\nCONFUSION MATRIX')
plt.figure(figsize= (6,4))
sns.heatmap(con_mat, annot = True,fmt='d',cmap="YlGnBu")

model_accuracy['Logistic Regression'] = log_reg_model.score(x_test,y_test)
pickle.dump(log_reg_model, open('Model_det_LR.pkl', 'wb'))

def pred(link):
    loaded_model = pickle.load(open('./Model_det_LR.pkl', 'rb'))
    
    sample =[]
    sample.append(link)
    df = pd.DataFrame(sample, columns=['url'])
    len_preprocess(df)
    df = df.drop("tld",1)
    count_preprocess(df)
    ip_process(df)
    df = df[['hostname_length',
       'path_length', 'fd_length', 'tld_length', 'count-', 'count@', 'count?',
       'count%', 'count.', 'count=', 'count-http','count-https', 'count-www', 'count-digits',
       'count-letters', 'count_dir', 'use_of_ip']]
    result = loaded_model.predict(df)
    if result[0] == 0:
        return 0
    else:
        return 1


link = input("Enter your link:\t")

print(pred(link))
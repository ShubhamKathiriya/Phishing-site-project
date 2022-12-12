from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import pickle
import pandas as pd
from tld import get_tld
from urllib.parse import urlparse
import re

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
model = pickle.load(open('Model_det_LR.pkl', 'rb'))
model_classify = pickle.load(open('Model_classification_etc.pkl', 'rb'))

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

def having_ip_address1(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

def ip_process(url_dataset):
    url_dataset['short_url'] = url_dataset['url'].apply(lambda i: shortening_service(i))
    url_dataset['use_of_ip'] = url_dataset['url'].apply(lambda i: having_ip_address(i))

def process_tld(url):
    try:
#         Extract the top level domain (TLD) from the URL given
        res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
        pri_domain= res.parsed_url.netloc
    except :
        pri_domain= None
    return pri_domain

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def httpSecure(url):
    htp = urlparse(url).scheme #It supports the following URL schemes: file , ftp , gopher , hdl , 
                               #http , https ... from urllib.parse
    match = str(htp)
    if match=='https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def Shortining_Service(url):
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
        return 1
    else:
        return 0

def URL_Converter(urls):
    data= pd.DataFrame()
    data['url'] = pd.Series(urls)

    
    data['url_len'] = data['url'].apply(lambda x: len(str(x)))
    data['domain'] = data['url'].apply(lambda i: process_tld(i))
    feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
    for a in feature:
        data[a] = data['url'].apply(lambda i: i.count(a))  
    data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))
    data['https'] = data['url'].apply(lambda i: httpSecure(i))
    data['digits']= data['url'].apply(lambda i: digit_count(i))
    data['letters']= data['url'].apply(lambda i: letter_count(i))
    data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))
    data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address1(i))
    #print(data.columns)
    X = data.drop(['url','domain'],axis=1)
    
    return X

@app.route('/detect',methods=['GET'])
@cross_origin()
def detect():
    URL = request.args.get('URL')

    sample =[]
    sample.append(URL)
    df = pd.DataFrame(sample, columns=['url'])
    len_preprocess(df)
    df = df.drop("tld",1)
    count_preprocess(df)
    ip_process(df)

    df = df[['hostname_length',
       'path_length', 'fd_length', 'tld_length', 'count-', 'count@', 'count?',
       'count%', 'count.', 'count=', 'count-http','count-https', 'count-www', 'count-digits',
       'count-letters', 'count_dir', 'use_of_ip']]
    prediction = model.predict(df)


    if(prediction[0] == 0):
        data = {'Safe': True, 'Type': 'NA'}
        return jsonify(data)
    else:
        test_data= URL_Converter(URL)
        prediction2 = model_classify.predict(test_data)
        data = {'Safe': False, 'Type': 'NA'}

        if prediction2[0] == 0:
            data['Type'] = 'Benign'
        elif prediction2[0] == 1:
             data['Type'] = 'Defacement'
        elif prediction2[0] == 2:
             data['Type'] = 'Phishing'
        else:
             data['Type'] = 'Malware'
        
        return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
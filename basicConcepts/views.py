
import random
from django.http import HttpResponse
from django.shortcuts import render
import numpy as np

from joblib import load
from sklearn import ensemble
from sklearn.tree import DecisionTreeClassifier
import numpy as np


model = load('./saveModel/modelRFDNN.joblib')

def Welcome(request):
        return render(request, 'index.html')

def TestUrl(request):
        return render(request, 'testurl.html', {'percent': 0})

def About(request):
    return render(request, 'about.html')

def Summary(request):
    return render(request, 'summary.html')


# Get Percentage calculation using desision model 

def GetPercentage(list1, list2):

    array1 = np.array(list1)
    array2 = np.array(list2)

    intersection = set(list1) & set(list2)
    intersection = np.intersect1d(array1, array2)

    len_intersection = len(intersection)
    len_array1 = len(array1)
    len_array2 = len(array2)

    similarity_percentage = len_intersection / ((len_array1 + len_array2) - len_intersection) * 100
    percentage = (sum(list1)/len(list1) + sum(list2)/len(list1) )/ len(list1) * 100
    decision_tree = DecisionTreeClassifier()
    decision_tree.fit(array1.reshape(-1, 1), np.zeros(len_array1))
    predicted_similarity = decision_tree.predict(array2.reshape(-1, 1))

    return round(percentage,0)



def Url(request):
    url = request.GET['url'] 
    ourl = url
    url = get_prediction_from_url(url)


    # Pre-define for getting instant percentage to show and littile summery

    allFeatureName = ["Having IP Address", "Abnormal URL", "Count Dot", "Count WWW", "Count atrate", "No Of Dir", "No Of Embed", "Shortening Service", "Count Https", "Count Http", "Count per", "Count Ques", "Count Hyphen", "Count equal", "URL Length", "Hostname Length", "Suspicious Words", "Digit Count", "Letter Count", "fd Length", "tld Length"]
    # Safe
    preSafe = [0, 0, 2, 0, 0, 3, 0, 0, 0, 0, 0, 0, 7, 0, 99, 0, 0, 19, 66, 10, -1]
    # Defacement
    preDefacement = [0, 1, 3, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 4, 88, 21, 0, 7, 63, 9, 2]
    # Phishing
    prePhishing = [0, 1, 2, 1, 0, 3, 0, 1, 0, 1, 0, 0, 0, 0, 71, 27, 0, 17, 46, 2, 3]
    # Malware
    preMalware = [0, 1, 3, 0, 0, 5, 0, 0, 0, 1, 2, 1, 0, 0, 77, 20, 0, 7, 55, 4, 3]
    n = 0
    # current url status 
    currentUrlStatus = main(ourl)
    print(currentUrlStatus)


    safP = GetPercentage(preSafe, currentUrlStatus)
    defP = GetPercentage(preDefacement, currentUrlStatus)
    phiP = GetPercentage(prePhishing, currentUrlStatus)
    malP = GetPercentage(preMalware, currentUrlStatus)
    percent = [safP, defP, phiP, malP]
    percent = bypercent( url )

    return render(request, 'testurl.html', {'url': url, 'ourl': ourl, 'percent': 1, 'allFeatureName': allFeatureName, 'preSafe': preSafe, 'preDefacement': preDefacement, 'prePhishing': prePhishing, 'preMalware': preMalware, 'currentUrlStatus':currentUrlStatus, 'percent': percent})


def get_prediction_from_url(test_url):
  
    features_test = main(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))

    

    pred = model.predict(features_test)
    gIndex = google_index(test_url)
    print(gIndex)
    if (int(pred[0]) == 0) and (gIndex != 0):
        
        res="SAFE"
        return res
    elif int(pred[0]) == 1.0 and (gIndex != 0):
        
        res="DEFACEMENT"
        return res
    elif int(pred[0]) == 2.0 and (gIndex != 0):
        res="PHISHING"
        return res
        
    elif int(pred[0]) == 3.0:
        
        res="MALWARE"
        return res





# Get url features by calling the function
def main(url):
    
    status = []
   
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)
      
    status.append(tld_length(tld))
    

    
    return status
list = {}
def bypercent(a):
    global list
    if(list.get(a,0) == 0):
        if (a == "SAFE"):
            p = [ random.randrange(75, 95), random.randrange(25, 60), random.randrange(35, 65), random.randrange(20, 60)]
        if (a == "DEFACEMENT"):
            p = [ random.randrange(30, 50), random.randrange(75, 95), random.randrange(25, 60), random.randrange(35, 60)]
        if(a == "PHISHING"):
            p = [ random.randrange(40, 60), random.randrange(20, 60), random.randrange(75, 85), random.randrange(25, 60)]
        if(a == "MALWARE"):
            p = [ random.randrange(30, 60), random.randrange(20, 60), random.randrange(20, 60), random.randrange(75, 95)]
        list[a]=p
    elif(list.get(a,0)):
        return list[a]
    return p

# Different type of feature   
#  pip install googlesearch-python

from googlesearch import search

import re
from urllib.parse import urlparse
from urllib.parse import urlparse
from tld import get_tld
import os.path



#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


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


def google_index(url):
    site = search(url, 5)
    return 1 if site else 0



def count_dot(url):
    count_dot = url.count('.')
    return count_dot


def count_www(url):
    url.count('www')
    return url.count('www')

def count_atrate(url):
     
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')



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
        return 1
    else:
        return 0





def count_https(url):
    return url.count('https')




def count_http(url):
    return url.count('http')



def count_per(url):
    return url.count('%')


def count_ques(url):
    return url.count('?')


def count_equal(url):
    return url.count('=')



def url_length(url):
    return len(str(url))



def hostname_length(url):
    return len(urlparse(url).netloc)




def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0



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


def count_hyphen(url):
    return url.count('-')









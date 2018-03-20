import requests
from bs4 import BeautifulSoup
import pandas as pd
from collections import deque
import re
from random import shuffle


used_proxies = set(["51.15.209.252:3128"])
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_7; en-us) AppleWebKit/534.16+ (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4'}

class FreeProxy(object,):
    """Get a list of free proxies for use with requests """
    
    def update_proxies(self, all_sources = False):
        """Update the list of available proxies from free-proxy-list.net"""
        site = 'https://free-proxy-list.net/'
        r = requests.get(site, headers = headers)
        self.proxies = pd.DataFrame()
             
        if r.status_code == 200:
            soup = BeautifulSoup(r.content, 'lxml')
            tableheaders = {0:'ip', 1:'port', 2:'code', 3:'country', 4: 'anonymity', 5:'google', 6:'https', 7:'checked'}
            table = soup.find(attrs={'id':'proxylisttable'})
    
            for row in table.findAll('tr'):
                info = {}
                for i, column in enumerate(row.findAll('td')):
                    info.update({tableheaders.get(i) :column.text})
                
                new_proxy = pd.DataFrame(pd.Series(info)).transpose()
                self.proxies = self.proxies.append(new_proxy)
                self.proxies = self.proxies.dropna()

        if (r.status_code != 200) or (all_sources == True):
            for country in ['France','Germany','Spain','Italy','Untited Kingdom','Poland','Netherlands','Denmark','czech republic']:
                site = 'http://www.gatherproxy.com/proxylist/country/?c='
                r = requests.get(site + country, headers = headers)
                if r.status_code==200:
                    soup = BeautifulSoup(r.content, 'lxml')
                    table = soup.find('table', attrs={'id':'tblproxy'})
            
                    for row in table.findAll('script'):
                        info = dict(string.split(':') for string in re.sub('"','',row.get_text().strip())[14:-3].split(','))
                        info.update({'PROXY_PORT':str(int(info.get('PROXY_PORT'),16))})
                        new_proxy = pd.DataFrame(pd.Series(info)).transpose()
                        new_proxy = new_proxy[['PROXY_IP','PROXY_PORT','PROXY_COUNTRY','PROXY_TYPE']]
                        new_proxy.rename(columns={'PROXY_IP':'ip','PROXY_PORT':'port','PROXY_COUNTRY':'country','PROXY_TYPE':'anonymity'}, inplace=True)
                        new_proxy = new_proxy.dropna()
                        new_proxy['https'] = 'yes'
                        self.proxies = self.proxies.append(new_proxy)
                
#            self.proxies = self.proxies[['PROXY_IP','PROXY_PORT','PROXY_COUNTRY','PROXY_TYPE']]
#            self.proxies.rename(columns={'PROXY_IP':'ip','PROXY_PORT':'port','PROXY_COUNTRY':'country','PROXY_TYPE':'anonymity'}, inplace=True)
#            self.proxies = self.proxies.dropna()
#            self.proxies['https'] = 'yes'

        
    def __init__(self):
        self.update_proxies()
        
    def set_proxylist(self, proxylist):
        """Use an external list of proxies instead of retrieving one from free-proxy-list.net"""
        self.proxies = proxylist
            
    def __proxyframe(self, country=None, https = True, anonymity = 'anonymous', port = None):
        candidates = self.proxies
        if country != None:
            candidates['country_match'] = [candidate_country in country for candidate_country in candidates.country]
            candidates = candidates[candidates['country_match'] == True].drop('country_match', axis=1)
        if https == True:
            candidates = candidates[candidates['https'] == 'yes']
        if port != None:
            candidates = candidates[candidates['port'] == port]
        if anonymity != None:
            if anonymity == 'elite':
                candidates = candidates[(candidates.anonymity.str.lower() == 'elite') | (candidates.anonymity.str.lower() == 'elite proxy') ]
            elif anonymity == 'anonymous':
                 candidates = candidates[(candidates.anonymity.str.lower() == 'elite proxy') | (candidates.anonymity.str.lower() == 'elite') | (candidates.anonymity.str.lower() == 'anonymous')]
        candidates['used_proxy'] = [ip in used_proxies for ip in candidates.ip]
        return candidates[candidates.used_proxy == False]

    def get_list(self, country=None, https = True, anonymity = 'anonymous', port = None, randomize =False):
        """Get a list of proxies that match criteria"""
        candidates = self.__proxyframe(country=country, https=https, anonymity=anonymity, port = port)
        proxielist = deque()
        for i,row in candidates.iterrows():
            proxy_dict = {'http': row.ip + ':' + row.port}
            if https == True:
                proxy_dict.update({'https': row.ip + ':' + row.port})
            proxielist.append(proxy_dict)
        if randomize == True:
            shuffle(proxielist)
        return proxielist
        
    def get_recent(self, country=None, https = True, anonymity = 'anonymous'):
        """Get the most recently checked proxy that matches criteria"""
        candidates = self.__proxyframe(country=country, https=https, anonymity=anonymity)
        candidates = candidates.head(1).reset_index(drop=True)
        proxy_dict = {'http': candidates.ip[0] + ':' + candidates.port[0]}
        if https == True:
            proxy_dict.update({'https': candidates.ip[0] + ':' + candidates.port[0]})
        return proxy_dict
        

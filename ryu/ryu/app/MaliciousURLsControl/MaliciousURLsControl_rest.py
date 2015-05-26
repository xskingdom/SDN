#Author: Xu Han
#data:2015.05.21
#Email:xskingdom@icould.com
'''
# get malicious URL list
# GET /Malicious/MaliciousURLs
#
# set decoyHost
# PUT /decoy/decoyHost
# body should be such as : "{"10.0.0.1":"00:00:00:00:00:01"}"
#
# get decoyHost
# GET /decoy/decoyHost
#
'''
import logging
import json
import os
import sys, urllib

from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.app.MaliciousURLsControl import MaliciousURLsControl
from webob import Response

from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3


LOG = logging.getLogger(__name__)

PATH = os.path.dirname(__file__)


instance_name = 'MaliciousURLsControl_api_app'

supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
}

class MaliciousURLsControl_rest(MaliciousURLsControl.MalURLsCtrl):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
            ofproto_v1_2.OFP_VERSION,
            ofproto_v1_3.OFP_VERSION]
    
    _CONTEXTS = { 'wsgi': WSGIApplication 
                 }
    
    def __init__(self, *args, **kwargs):
        super(MaliciousURLsControl_rest, self).__init__(*args, **kwargs)  
        wsgi = kwargs['wsgi']
        self.data = {}
        self.data[instance_name] = self

        mapper = wsgi.mapper
        #wsgi.register(DecoyController, {instance_name : self,'Switches':self.Switches,'waiters':self.waiters})
        wsgi.registory['MaliciousURLsController'] = self.data
        
        path = '/Malicious/'
              
        uri = path+'MaliciousURLs'
        mapper.connect('Malicious', uri,
                       controller=MaliciousURLsController, action='get_urls',
                       conditions=dict(method=['GET']))     
        
        uri = path+'decoyHost'
        mapper.connect('Malicious', uri,
                       controller=MaliciousURLsController, action='add_decoyHost',
                       conditions=dict(method=['PUT']))   
 
        mapper.connect('Malicious', uri,
                       controller=MaliciousURLsController, action='list_decoyHost',
                       conditions=dict(method=['GET']))                     

class MaliciousURLsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(MaliciousURLsController, self).__init__(req, link, data, **config)
        self.mal_app = data[instance_name]

    def get_urls(self, req, **kwargs): 
        mal = self.mal_app      
        url = "http://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
        wp = urllib.urlopen(url) 
        content = wp.read()
        ipCont=content.split('\n',7)
        ipCont=ipCont[7]
        ipList=ipCont.split('\n');
        ipAll=[]
        for ip in ipList:
            ip.strip()          
            if ip:
                numip=ip.split('.')
                if len(numip)==4:
                   flag=0
                   for num in numip:
                       if int(num)>=0 and int(num)<=255:
                          continue
                       else:
                            flag=1
                            break
                   if flag==0:
                        ipAll.append(ip)
        mal.MaliciousURLs = ipAll
        body = json.dumps(mal.MaliciousURLs)
        return Response(content_type='application/json', body=body)
    
    def list_decoyHost(self, req, **kwargs):
        mal = self.mal_app
        host = mal.decoyHost           
        body = json.dumps(host)
        return Response(content_type='application/json', body=body)
    
    def add_decoyHost(self, req, **kwargs):
        mal = self.mal_app
        host = eval(req.body)
        ip = host.keys()[0]
        mac = host[ip]
        length = len(host)
        if length == 1:
            mal.decoyHost.clear()
            mal.decoyHost[ip] = mac
            body = json.dumps(mal.decoyHost)
        else:
            body = json.dumps("Should PUT only one MAC address!")
        return Response(content_type='application/json', body=body)    

app_manager.require_app('ryu.app.MaliciousURLsControl.ws_URLs')
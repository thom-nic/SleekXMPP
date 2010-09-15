'''
Created on Sep 2, 2010

@author: bbeggs
'''
from . import base
import os
import random
import logging
import hashlib
from .. xmlstream.stanzabase import ElementBase, ET
from xml.etree.cElementTree import XML, tostring
from sleekxmpp.xmlstream.stanzabase import ElementBase
from sleekxmpp.xmlstream.handler.xmlcallback import XMLCallback
from sleekxmpp.xmlstream.matcher.xmlmask import MatchXMLMask
import time

PROTOCOL_SI_XMLNS            = 'http://jabber.org/protocol/si'
PROTOCOL_SI_PROFILE_FT_XMLNS = 'http://jabber.org/protocol/si/profile/file-transfer'
PROTOCOL_FEATURENEG_XMLNS    = 'http://jabber.org/protocol/feature-neg'

def generateSid():
    sid = ''
    for i in range(7):
        sid+=hex(int(random.random()*65536*4096))[2:]
    return sid[:8].upper()

class FileTransferProtocol(object):
    FILE_FINISHED_SENDING = 'BYTE_STREAM_SENDING_COMPLETE'
    FILE_FINISHED_RECEIVING = 'BYTE_STREAM_RECEIVING_COMPLETE'
    
    XMLNS = '' #MUST be overwritten by the implementer to be the namespace for
               #the implementing protocol
    
    def sendFile(self, fileName, to, threaded=True, sid=None):
        pass
    
    def getSessionStatus(self, sid):
        pass
    
    def getSessionStatusAll(self):
        pass
    
    def cancelSend(self, sid): 
        pass
    
    def acceptTransfer(self, txInfo):
        pass
    
    def fileFinishedReceiving(self, sid, filename):
        self.xmpp.event(FileTransferProtocol.FILE_FINISHED_RECEIVING, {'sid': sid, 'filename':filename})
    
    def fileFinishedSending(self, sid):
        self.xmpp.event(FileTransferProtocol.FILE_FINISHED_SENDING, {'sid': sid})        
        
    '''
    Upon receipt of a file the following event should be created:
    xmpp.event(FILE_FINISHED_RECEIVING, {'sid': self.sid, 'filename':self.getSavedFileName()})
    '''
    
    
class xep_0096(base.base_plugin):
    '''
    
    openTransfer(dict) where {'sid', 'name', 'size', 'hash', 'protocolNS'}
    
    acceptTransfer(dict) where dict is {'sid', 'name', 'size', 'hash', 'protocolNS'}
    
    closeTransfer(dict) where {'sid', 'name', 'size', 'hash', 'protocolNS', 'savedPath'}
        #TODO is error needed?
        
    '''
    def plugin_init(self):
        self.xep = '0096'
        self.description = 'SI File Transfer'
        
        self.bytestreamProtocols = {}
        self.activeBytestreams = {}
        self.preferredProtocolNS = self.config.get('preferredProtocolNS', None)
        
        self.acceptTransfers = True
        self.saveDirectory = self.config.get('saveDirectory', '/tmp/')
        self.saveNamePrefix = self.config.get('saveNamePrefix', 'xep_0096_')        
        self.overwriteFile = self.config.get('overwriteFile', True)
        self.stanzaType = self.config.get('stanzaType', 'iq') #Currently only IQ is supported
        self.maxSessions = self.config.get('maxSessions', 2)
        
        #callbacks
        self.acceptTransferCallback = self.config.get('acceptTransferCallback')
        self.fileNameCallback = self.config.get('fileNameCallback')
        self.closeTransferCallback = self.config.get('closeTransferCallback')
        
        self.xmpp.registerHandler(XMLCallback('xep_0047_open_stream', 
                                              MatchXMLMask("<iq xmlns='%s' type='set'><si xmlns='%s'/></iq>" %(self.xmpp.default_ns, PROTOCOL_SI_XMLNS)),
                                              self._handleIncomingTransferRequest, 
                                              thread=True))
        self.xmpp.add_event_handler(FileTransferProtocol.FILE_FINISHED_RECEIVING, self._receiveCompleteHandler, True, False)
        self.xmpp.add_event_handler(FileTransferProtocol.FILE_FINISHED_SENDING, self._sendCompleteHandler, True, False)
      
    def post_init(self):
        if self.xmpp.plugin.get('xep_0030'):
            self.xmpp.plugin['xep_0030'].add_feature(PROTOCOL_SI_XMLNS)
            self.xmpp.plugin['xep_0030'].add_feature(PROTOCOL_SI_PROFILE_FT_XMLNS)
          
    def add_feature(self, namespace, protocol, rangeSupport = False):
        '''
        A bytestream protocol must implement FileTransferProtocol class.
        '''
        self.bytestreamProtocols[namespace] = {'protocol' : protocol, 'rangeSupport' : rangeSupport}
        
    def setPreferredProtocol(self, protocolNS):
        if self.bytestreamProtocols.get(protocolNS, None):
            self.preferredProtocolNS = protocolNS
        else:
            raise Exception('Unknown protocol namespace: %s' %protocolNS)
        
    def acceptTransferRequest(self, xferInfo, xml):
        if self.acceptTransferCallback:
            return self.acceptTransferCallback(xml)
        else:
            return self.acceptTransfers
        
    def protocolGetAcceptTransferRequest(self, sid):
        '''
        Bytestream protocols implementing FileTransferProtocol should call this
        method to determine if a bytestream initiation request should be accepted
        '''
        if self.activeBytestreams.get(sid):
            return True
        else:
            return False
    
    def protocolGetFilename(self, sid):
        '''
        Bytestream protocols implementing FileTransferProtocol should call this
        method to get the filename for a newly opened bytestream.
        '''
        return self.activeBytestreams.get(sid)['filenameAndPath']
        
    
    def _handleIncomingTransferRequest(self, xml):
        logging.debug("incoming file transfer request: %s" %tostring(xml))
        
        xferInfo = parseRequestXMLToDict(xml)
        returnIQ = None
        
        #Check the current number of transfering going isn't more than allowed
        numTranfers = 0
        for protocol in self.bytestreamProtocols.values():
            numTranfers += len(protocol['protocol'].getSessionStatusAll())
        if numTranfers >= self.maxSessions:
            returnIQ = makeRejectStreamIQ(self.xmpp.makeIqError(xml.get('id')), xferInfo['otherParty'])
            
        #Check if the program is accepting transfers
        if self.acceptTransferRequest(xferInfo, xml) == False and returnIQ is None:
            logging.debug('rejecting transfer')
            returnIQ = makeRejectStreamIQ(self.xmpp.makeIqError(xml.get('id')), xml.get('to'))
        
        #check that the requested protocol is a feature available for use
        #s1 = set([x for x in self.bytestreamProtocols.iterkeys()])
        matchingProtocols = set(self.bytestreamProtocols.keys()).intersection(xferInfo['protocols'])
        if len(matchingProtocols) == 0 and returnIQ is None:
            returnIQ = makeNoValidStreamsIQ(self.xmpp.makeIqError(xml.get('id')), xml.get('to'))
         
            
        #None of the error conditions is true, we can accept the transfer
        if returnIQ is None:
            logging.debug('transfer accepted, sending ')
            #get the full filename and save path
            self.activeBytestreams[xferInfo['sid']] = xferInfo
            filenameAndPath = self.saveDirectory + self.saveNamePrefix + xferInfo['filename']
            if self.fileNameCallback:
                filenameAndPath = self.fileNameCallback(sid=xferInfo['sid'], xml=xml)
            xferInfo['filenameAndPath'] = filenameAndPath
            #Figure out which protocol to use
            #if there is no preferred protocol pop a matching 
            protocolNS = None
            if self.preferredProtocolNS:
                protocolNS = self.preferredProtocolNS
            else:  
                protocolNS = matchingProtocols.pop()
            xferInfo['selectedProtocol'] = self.bytestreamProtocols[protocolNS]['protocol']
            
            returnIQ = makeAcceptResultIQ(self.xmpp.makeIqResult(xml.get('id')), xml.get('from'), protocolNS)
                        
        returnIQ.send(priority=2, block=False)   
        
    def _receiveCompleteHandler(self, dict):
        xferInfo = self.activeBytestreams.pop(dict['sid'], None)
        if self.closeTransferCallback:
            self.closeTransferCallback(xferInfo)
        
    def _sendCompleteHandler(self, dict):
        xferInfo = self.activeBytestreams.pop(dict['sid'], None)
        if self.closeTransferCallback:
            self.closeTransferCallback(xferInfo)
    
    def sendFile(self, fileName, to, threaded=True):
        logging.debug('sending file...')
        #verify the file exists
        if not os.path.isfile(fileName):
            raise IOError('file: %s not found' %fileName)
        
        sid = generateSid()
        md5 = hashlib.md5()
        with open(fileName) as f:
            while True:
                data = f.read(4096)
                if data == str(''): break
                md5.update(data)
        iq = makeStreamOfferIQ(self.xmpp.makeIqSet(), 
                               to, 
                               sid, 
                               self.bytestreamProtocols.keys(), 
                               fileName[fileName.rfind('/') + 1:], 
                               os.path.getsize(fileName),
                               fileHash=md5.hexdigest())
        result = iq.send(block=True, priority=1, timeout=10)
        if result.get('type') == 'error': 
            logging.debug('session rejected')
            raise Exception('Session rejected: %s' %result)
            '''
            if result.find('*/{urn:ietf:params:xml:ns:xmpp-stanzas}service-unavailable') != None:
                raise Exception('user not online! User: %s' %to)
            elif result.find('*/{urn:ietf:params:xml:ns:xmpp-stanzas}not-acceptable') != None:
                raise NotAcceptableException('Error setting up the stream, receiver not ready %s' %result)
            else:
                raise Exception('Unknown error! %s' %result)
            '''
            
        self.activeBytestreams[sid] = parseRequestXMLToDict(iq.xml)
        #get the negoiated protocol and send the file
        protocol = result.xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}value')[0].text
        self.activeBytestreams[sid]['selectedProtocol'] = self.bytestreamProtocols[protocol]['protocol']
        self.activeBytestreams[sid]['selectedProtocol'].sendFile(fileName, to, threaded, sid)
        return sid
        
    def getSessionStatus(self, sid):
        return self.activeBytestreams[sid]['selectedProtocol'].getSessionStatus(sid)
        
    def getSessionStatusAll(self):
        sessions = {}
        for protocol in self.bytestreamProtocols.values():
            sessions.update(protocol['protocol'].getSessionStatusAll())
        return sessions
    
    def cancelSend(self, sid):
        self.activeBytestreams[sid]['selectedProtocol'].cancelSend(sid)
    
def parseRequestXMLToDict(xml):
    #Get the info on the request parse the inportant info in to a dict
    xferInfo = {}
    xferInfo['otherParty'] = xml.get('from')
    xferInfo['sid'] = xml.find('.//{http://jabber.org/protocol/si}si').get('id')
    elem = xml.find('.//{http://jabber.org/protocol/si}si/{http://jabber.org/protocol/si/profile/file-transfer}file')
    xferInfo['filename'] = elem.get('name')
    xferInfo['filesize'] = elem.get('size')
    xferInfo['filehash'] = elem.get('hash')
    xferInfo['filedate'] = elem.get('date') 
    protocols = []
    items = xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}option/{jabber:x:data}value')
    for elem in xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}option/{jabber:x:data}value'):
        protocols.append(elem.text)
    xferInfo['protocols'] = protocols 
    xferInfo['startTime'] = time.time()
    return xferInfo 

def makeAcceptResultIQ(iq, to, protocol_ns):
    iq['to'] = to
    si = ET.Element('{%s}si' %PROTOCOL_SI_XMLNS)
    elem = ET.SubElement(si, '{%s}feature' %PROTOCOL_FEATURENEG_XMLNS)
    elem = ET.SubElement(elem, '{jabber:x:data}x', type='submit')
    elem = ET.SubElement(elem,'field', var='stream-method')
    elem = ET.SubElement(elem, 'value')
    elem.text = protocol_ns
    iq.setPayload(si)
    return iq
    
def makeRejectStreamIQ(iq, to):
    iq['to'] = to
    iq['type'] = 'error'
    return makeErrorIQ(iq, to, '403', 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}forbidden',
                       None, 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}text', 
                       'Offer Declined')
    
def makeNoValidStreamsIQ(iq, to):
    iq['to'] = to
    iq['type'] = 'error'
    return makeErrorIQ(iq, to, '400', 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}bad-request',
                       None, 
                       '{http://jabber.org/protocol/si}no-valid-streams', 
                       None)

def makeProfileNotUnderstoodIQ(iq, to):
    iq['to'] = to
    iq['type'] = 'error'
    return makeErrorIQ(iq, to, '400', 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}bad-request',
                       None, 
                       '{http://jabber.org/protocol/si}bad-profile', 
                       None)    


def makeErrorIQ(iq, to, errCode, elem0NS, elem0Txt=None, elem1NS=None, elem1Txt=None):
    iq['to'] = to
    error = ET.Element('error', code=str(errCode), type='cancel')
    for ns, txt in [(elem0NS, elem0Txt), (elem1NS, elem1Txt)]:
        if ns is not None:
            elem = ET.SubElement(error, ns)
            if txt is not None:
                elem.text = txt
    iq.setPayload(error)
    return iq

def makeStreamOfferIQ(iq, to, sid, protocolNS, fileName, fileSize=None, fileHash=None, fileDate=None, fileDesc=None):
    iq["to"] = to
    si = ET.Element('{%s}si' %PROTOCOL_SI_XMLNS, id=sid, profile=PROTOCOL_SI_PROFILE_FT_XMLNS)
    si.attrib['mime-type']='text/plain'
    elem = ET.SubElement(si, '{%s}file' %PROTOCOL_SI_PROFILE_FT_XMLNS)
    for k, v in [('name',fileName), ('size',str(fileSize)), ('hash',fileHash), ('date',fileDate)]:
        if v:
            elem.attrib[k] = v
    if fileDesc:
        desc = ET.SubElement(elem, 'desc')
        desc.text = fileDesc
    
    elem = ET.SubElement(si, '{%s}feature' %PROTOCOL_FEATURENEG_XMLNS)
    elem = ET.SubElement(elem, '{jabber:x:data}x', type='form')
    field = ET.SubElement(elem, '{jabber:x:data}field', var='stream-method', type='list-single')
    for protocol in protocolNS:
        elem = ET.SubElement(field, '{jabber:x:data}option')
        elem = ET.SubElement(elem, '{jabber:x:data}value')
        elem.text = protocol
    
    iq.setPayload(si)
    return iq
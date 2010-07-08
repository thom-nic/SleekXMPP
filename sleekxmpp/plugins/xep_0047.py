'''
Created on Jul 1, 2010

@author: bbeggs
'''
from . import base
import logging
import threading
import time
from .. xmlstream.stanzabase import ElementBase, ET, JID
from sleekxmpp.stanza.error import Error
from sleekxmpp.stanza.iq import Iq
from sleekxmpp.xmlstream.handler.xmlcallback import XMLCallback
from sleekxmpp.xmlstream.matcher.xmlmask import MatchXMLMask
from xml.etree.ElementTree import tostring

XMLNS = 'http://jabber.org/protocol/ibb'

class xep_0047(base.base_plugin):
    '''
    In-band file transfer for __xmpp.
    
    Both message and iq transfer is supported with message being attempted first.
    '''
       
    def plugin_init(self):
        self.xep = 'xep-047'
        self.description = 'in-band file transfer'
        self.acceptTransfers = self.config.get('acceptTransfers', True)
        self.saveDirectory = self.config.get('saveDirectory', '/tmp')
        self.saveNamePrefix = self.config.get('saveNamePrefix', 'xep_0047_')
        self.overwriteFile = self.config.get('overwriteFile', True)
        self.stanzaType = self.config.get('stanzaType', 'iq')
        self.maxSendThreads = self.config.get('maxSendThreads', 1)
        self.maxReceiveThreads = self.config.get('maxReceiveThreads', 1)
        
        #thread setup
        self.receiveThreads = {} #id:thread
        self.sendThreads = {}
        
        #add handlers to listen for incoming requests
        self.xmpp.add_handler("<iq type='set'><open xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleIncomingTransferRequest, threaded=True)
        self.xmpp.add_handler("<iq type='set'><close xmlns='http://jabber.org/protocol/ibb' /></iq>", self.streamClosed, threaded=True)
        
    def post_init(self):
        self.post_inited = True
        
    def sendFile(self, filePath, threaded=True):
        #TODO use this method to send a file
        logging.debug("About to send file: %s" %filePath)   
    
    def _handleIncomingTransferRequest(self, xml):
        logging.debug("incoming request to open file transfer stream")
        logging.debug(tostring(xml))
        if self.acceptTransfers and len(self.receiveThreads) < self.maxReceiveThreads:
            elem = xml.find('{%s}' %XMLNS + 'open')
            self.receiveThreads[elem.get('sid')] = ReceiverThread(caller=self, xmpp=self.xmpp, sid=elem.get('sid'))
            self.receiveThreads[elem.get('sid')].start()
            self.sendAck(to=xml.get('from'), id=xml.get('id'))
        else: #let the requesting party know we are not accepting file transfers 
            iq = self.xmpp.makeIqError(id=xml.get('id'))
            iq['to'] = xml.get('from')
            iq['error']['type'] = 'cancel'
            iq.setCondition('not-acceptable')
            iq.send()
        
    def streamClosed(self, xml):
        elem = xml.find('{%s}' %XMLNS + 'close')
        sid = elem.get('sid')
        
        thread = None
        if self.receiveThreads.get(sid):
            thread = self.receiveThreads.get(sid)
            del self.receiveThreads[sid]
        elif self.sendThreads.get(sid):
            thread = self.sendThreads.get(sid)
            del self.sendThreads[sid]
        else: #We don't know about this stream, send error
            iq = self.xmpp.makeIqError(id=xml.get('id'))
            iq['to'] = xml.get('from')
            iq['error']['type'] = 'cancel'
            iq.setCondition('item-not-found')
            iq.send()

        if thread:
            thread.handleEndStream()
            thread.join(5)
            del thread
            self.sendAck(xml.get('from'), xml.get('id'))
        
    def sendCloseStream(self, to, sid):
        close = ET.Element('{%s}close' %XMLNS, sid=sid)
        iq = self.xmpp.makeIqSet()
        iq['to'] = to
        iq.setPayload(close)
        iq.send()
        
    def sendAck(self, to, id):
        iq = self.xmpp.makeIqResult(id=id)
        iq['to'] = to
        iq.send()
        
    
class ReceiverThread(threading.Thread):
    
    def __init__(self, caller, xmpp, sid):
        self.processPackets = True
        self.__caller = caller
        self.__xmpp = xmpp
        self.__sid = sid
        self.__payloads = []
        threading.Thread.__init__(self, name='receive_thread_%s' %sid)
        
        #register to start receiving file packets
        self.__xmpp.registerHandler(XMLCallback('file_receiver_message_%s' %self.__sid, MatchXMLMask("<message><data xmlns='%s' sid='%s' /></message>" %(XMLNS, self.__sid)), self.handlePacket, False, False, False))
        self.__xmpp.registerHandler(XMLCallback('file_receiver_iq_%s' %self.__sid, MatchXMLMask("<iq type='set'><data xmlns='%s' sid='%s' /></iq>" %(XMLNS, self.__sid)), self.handlePacket, False, False, False))
    
        
    def run(self):
        while self.processPackets or len(self.__payloads) > 0:
            logging.debug("packet processing for __sid %s" %self.__sid)
            time.sleep(2)
            #TODO: add packet processing logic

        logging.debug("finished processing packets")
        
    def handlePacket(self, xml):
        elem = xml.find('{%s}' %XMLNS + 'data')
        self.__payloads.append(elem.text)
       
        if 'iq' in xml.tag.lower():
            self.__caller.sendAck(xml.get('from'), xml.get('id'))
      
    def handleEndStream(self):
        logging.debug("end of stream. remove data handlers")
        #remove the file handlers, stream has ended
        self.__xmpp.removeHandler('file_receiver_message_%s' %self.__sid)
        self.__xmpp.removeHandler('file_receiver_iq_%s' %self.__sid)
        #TODO: signal the thread runner to assemble the packets and save the file
        self.processPackets = False
        
    
class SenderThread(threading.Thread):
    def __init__(self):
        pass
    
    def run(self):
        pass
    
    def handleEndStream(self):
        pass
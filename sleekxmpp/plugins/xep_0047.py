'''
Created on Jul 1, 2010

@author: bbeggs
'''
from __future__ import division, with_statement, unicode_literals
from . import base
import os
try:
    import queue
except ImportError:
    import Queue as queue
import logging
import threading
import time
import random
import base64
from .. xmlstream.stanzabase import ElementBase, ET, JID
from sleekxmpp.stanza.error import Error
from sleekxmpp.stanza.iq import Iq
from sleekxmpp.xmlstream.handler.xmlcallback import XMLCallback
from sleekxmpp.xmlstream.matcher.xmlmask import MatchXMLMask
from xml.etree.cElementTree import tostring
 
XMLNS = 'http://jabber.org/protocol/ibb'
STREAM_CLOSED_EVENT = 'BYTE_STREAM_CLOSED'

def sendAckIQ(xmpp, to, id):
    iq = xmpp.makeIqResult(id=id)
    iq['to'] = to
    iq.send(priority=1)
    
def sendCloseStream(xmpp, to, sid):
    close = ET.Element('{%s}close' %XMLNS, sid=sid)
    iq = xmpp.makeIqSet()
    iq['to'] = to
    iq.setPayload(close)
    iq.send(priority=1)
    
    
def generateSid():
    sid = ''
    for i in range(7):
        sid+=hex(int(random.random()*65536*4096))[2:]
    return sid[:8].upper()


class xep_0047(base.base_plugin):
    '''
    In-band file transfer for xmpp.
    
    Currently only IQ transfer is supported
    '''
       
    def plugin_init(self):
        self.xep = 'xep-047'
        self.description = 'in-band file transfer'
        self.acceptTransfers = self.config.get('acceptTransfers', True)
        self.saveDirectory = self.config.get('saveDirectory', '/tmp')
        self.saveNamePrefix = self.config.get('saveNamePrefix', 'xep_0047_')
        self.overwriteFile = self.config.get('overwriteFile', True)
        self.stanzaType = self.config.get('stanzaType', 'iq')
        self.maxSessions = self.config.get('maxSessions', 2)
        self.transferTimeout = self.config.get('transferTimeout', 120) #how long we should wait between data messages until we consider the stream invalid
        self.maxBlockSize = self.config.get('maxBlockSize', 8192)
        self.prefBlockSize = self.config.get('prefBlockSize', 4096)
        
        #thread setup
        self.streamSessions = {} #id:thread
        self.__streamSetupLock = threading.Lock()
        #add handlers to listen for incoming requests
        self.xmpp.add_handler("<iq type='set'><open xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleIncomingTransferRequest, threaded=True)
        self.xmpp.add_handler("<iq type='set'><close xmlns='http://jabber.org/protocol/ibb' /></iq>", self._handleStreamClosed, threaded=False)
        #Event handler to allow session threads to call back to the main processor to remove the therad
        self.xmpp.add_event_handler(STREAM_CLOSED_EVENT, self._eventCloseStream, threaded=True, disposable=False)
        
    def post_init(self):
        self.post_inited = True
        
    def sendFile(self, fileName, to, threaded=True):
        '''
        Sends a file to the intended receiver if the receiver is available and 
        willing to accept the transfer.  If the send is requested to be threaded 
        the session sid will be returned, otherwise the method will block until 
        the file has been sent and the session closed.
        
        The returned sid can be used to check on the status of the transfer or 
        cancel the transfer.
        
        Error Conditions:
        -IOError will be raised if the file to be sent is not found
        -TooManySessionsException will be raised if there are already more than 
        self.maxSessions running (configurable via plugin configuration)
        -Exception will be raised if the sender is not available
        -Exception will be raised if the sender denys the transfer request
        -InBandFailedException will be raised if there is an error during the
        file transfer
        '''
        #Init the stream with the receipent
        logging.debug("About to send file: %s" %fileName)   
        with self.__streamSetupLock:
            if len(self.streamSessions) > self.maxSessions:
                raise TooManySessionsException()
            
            if not os.path.isfile(fileName):
                raise IOError('file: %s not found' %fileName)
            
            sid = generateSid()
            iq = self.xmpp.makeIqSet()
            iq['to'] = to
            openElem = ET.Element('{%s}open' %XMLNS, sid=sid, stanza=self.stanzaType)
            openElem.set('block-size', str(self.prefBlockSize))
            iq.setPayload(openElem)
            result = iq.send(block=True, timeout=10, priority=1)
            if result.get('type') != 'result':
                #error setting up the stream
                raise Exception('Error setting up the stream %s' %tostring(result))
            
            self.streamSessions[sid] = ByteStreamSession(self.xmpp, sid, to, self.transferTimeout, self.prefBlockSize)
            
        self.streamSessions[sid].start()
        self.streamSessions[sid].sendFile(fileName, threaded)
    
    def getSendStatus(self, sid):
        '''
        Returns the status of the transfer specified by the sid
        '''
        session = self.streamSessions.get(sid)
        if session:
            return session.getStatus()
        else:
            return None
    
    def cancelSend(self, sid):
        '''
        cancels an outgoing file transfer.
        If the session is not found, method will pass
        '''
        session = self.streamSessions.get(sid)
        if session:
            session.cancelStream()
            
    def setAcceptStatus(self, status):
        '''
        sets if xep_0047 plugin will accept in-band file transfers or not.
        if switching from true to false any currently working sessions will 
        finish
        '''
        self.acceptTransfers = status
        
    def _handleIncomingTransferRequest(self, xml):
        logging.debug("incoming request to open file transfer stream")
        logging.debug(tostring(xml))
        elem = xml.find('{%s}' %XMLNS + 'open')
        with self.__streamSetupLock:
            if(self.maxBlockSize < int(elem.get('block-size'))):
                iq = self.xmpp.makeIqError(id=xml.get('id'), condition='resource-constraint')
                iq['to'] = xml.get('from')
                iq['error']['type'] = 'modify'
                iq.send(priority=1)
                pass
            
            if self.acceptTransfers and len(self.streamSessions) < self.maxSessions and not self.streamSessions:
                self.streamSessions[elem.get('sid')] = ByteStreamSession(self.xmpp, elem.get('sid'), xml.get('from'), self.transferTimeout, int(elem.get('block-size')), self.saveDirectory, self.saveNamePrefix + elem.get('sid'))
                self.streamSessions[elem.get('sid')].start()
                sendAckIQ(xmpp=self.xmpp, to=xml.get('from'), id=xml.get('id'))
            else: #let the requesting party know we are not accepting file transfers 
                iq = self.xmpp.makeIqError(id=xml.get('id'), condition='not-acceptable')
                iq['to'] = xml.get('from')
                iq['error']['type'] = 'cancel'
                iq.send(priority=1)
        
    def _handleStreamClosed(self, xml):
        '''
        Called when a stream closed event is received.
        '''
        elem = xml.find('{%s}' %XMLNS + 'close')
        sid = elem.get('sid')
        
        if self.streamSessions.get(sid):
            with self.__streamSetupLock:
                session = self.streamSessions.get(sid)
                del self.streamSessions[sid]
                session.process = False
                session.join(5)
                del session
                sendAckIQ(self.xmpp, xml.get('from'), xml.get('id'))
        else: #We don't know about this stream, send error
            iq = self.xmpp.makeIqError(id=xml.get('id'), condition='item-not-found')
            iq['to'] = xml.get('from')
            iq['error']['type'] = 'cancel'
            iq.send(priority=1)
            
    def _eventCloseStream(self, eventdata):
        '''
        Allows the session thread to 
        notify xep_0047 that a stream error has occurred or the stream has 
        finished and the session object should be disposed.
        '''
        with self.__streamSetupLock:
            session = self.streamSessions[eventdata['sid']]
            del self.streamSessions[eventdata['sid']]
            session.join(60)
            del session
        
        
class ByteStreamSession(threading.Thread):
    
    def __init__(self, xmpp, sid, otherPartyJid, timeout,  blockSize, recFilePath = None, recFileName = None):
        threading.Thread.__init__(self, name='bytestream_session_%s' %sid)
        self.process = True
        self.__xmpp = xmpp
        self.__payloads = queue.Queue()
        self.__incSeqId = -1
        self.__outSeqId = -1
        self.__incSeqLock = threading.Lock()
        self.__outSeqLock = threading.Lock()
        self.__closeStreamLock = threading.Lock()
        self.streamClosed = False
        self.__lastMessage = time.time()
        self.__sendFile = None
        self.__wfile = None
        self.__sendThread = None
        
        #block size needs to be a multiple of 4 for base 64 encoding, step
        #the number down till it is divisible by 4 so we can fit in under the 
        #base64 encoded size
        while blockSize % 4 != 0:
            blockSize -= 1
        self.__blockSize = blockSize
        
        self.sid = sid
        self.timeout = timeout
        self.recFilePath = recFilePath 
        self.recFileName = recFileName
        
        self.otherPartyJid = otherPartyJid
        #register to start receiving file packets
        self.__xmpp.registerHandler(XMLCallback('file_receiver_message_%s' %self.sid, MatchXMLMask("<message><data xmlns='%s' sid='%s' /></message>" %(XMLNS, self.sid)), self._handlePacket, False, False, False))
        self.__xmpp.registerHandler(XMLCallback('file_receiver_iq_%s' %self.sid, MatchXMLMask("<iq type='set'><data xmlns='%s' sid='%s' /></iq>" %(XMLNS, self.sid)), self._handlePacket, False, False, False))
        #self.__xmpp.registerHandler(XMLCallback('file_receiver_iq_%s' %self.__sid, MatchXMLMask("<iq type='result' from=''/>" %(XMLNS, self.__sid)), self._handlePacket, False, False, False))
        
    def getSavedFileName(self):
        if self.recFilePath and self.recFileName:
            return self.recFilePath + '/' + self.recFileName
        else:
            return None
        
    def run(self):
        if self.recFilePath and self.recFileName:
            self.__wfile = open(self.getSavedFileName(), 'wb')
            
        while self.process:
            logging.debug("seconds since last message: %f" %self.__lastMessage)
            if time.time() - self.__lastMessage <= self.timeout: 
                time.sleep(2)
            else: # no file to send and the file transfer has timed out, close up the stream
                logging.info('file transfer timeout')
                self._closeStream()
                break
        
        logging.debug("end of stream. remove data handlers")
        #remove the file handlers, stream has ended
        self.__xmpp.removeHandler('file_receiver_message_%s' %self.sid)
        self.__xmpp.removeHandler('file_receiver_iq_%s' %self.sid)
        if self.__sendThread:
            del self.__sendThread
        
        #close the file hander 
        if self.__wfile:
            self.__wfile.close()
        logging.debug("finished processing packets")
        
    def getNextIncSeqId(self):
        with self.__incSeqLock:
            self.__incSeqId += 1
            return self.__incSeqId
    
    def getNextOutSeqId(self):
        with self.__outSeqLock:
            self.__outSeqId += 1
            return self.__outSeqId
        
    def _handlePacket(self, xml):
        #ensure the data packet is from the other party we are conversing with
        #and the data is in the correct order
        self.__lastMessage = time.time()
        elem = xml.find('{%s}' %XMLNS + 'data')
        logging.debug('packet size: %s' %len(elem.text) )
        nextSeqId = self.getNextIncSeqId()
        if xml.get('from') == self.otherPartyJid and long(elem.get('seq')) == nextSeqId and len(elem.text) <= self.__blockSize:
            if self.__wfile: #write the file being sent if we have been giving somewhere to write it to
                self.__wfile.write(base64.decodestring(elem.text))
            
            #for IQ stanzas we must return a result
            if 'iq' in xml.tag.lower():
                sendAckIQ(self.__xmpp, xml.get('from'), xml.get('id'))
        else: 
            '''
            packet not in correct order or bad sender
            Ignore the input... Should we close the stream, something is wrong
            if we get a packet from a different user on this byte stream.  Could
            possibly be an attack
            TODO: cleanup, remove the file
            ''' 
            logging.warning('Bad file transfer packet received! Terminating session with %s' %self.otherPartyJid)
            logging.error('seq #: %s expected seq: %i' %(elem.get('seq'), nextSeqId) )
            logging.error('packet size: %s' %len(elem.text))
            self.process = False
            self._closeStream()
                
    def getStatus(self):
        #TODO: implement this method and figure out the return type, just just a dict of items.
        return {}
    
    def cancelStream(self):
        self.process = False
        while self.isAlive():
            time.sleep(.5)
        self._closeStream()
        if self.getSavedFileName():
            os.remove(self.getSavedFileName())
        
    
    def sendFile(self, fileName, threaded=False):
        if self.__sendThread:
            raise TooManySessionsException('Can only send 1 file per byte stream')

        self.__sendThread = threading.Thread(target=self._sendFile, name='Byte_Stream_Session_sender_%s' %self.sid, args=[fileName])
        self.__sendThread.start()
        
        if not threaded: #Block until the send is finished 
            self.__sendThread.join()
            
    def _sendFile(self, fileName):
        with open(fileName, 'rb') as file:
            fileReadSize = int(self.__blockSize / (4/3))
            while self.process:
                data = file.read(fileReadSize)
                if data == '': break
                iq = self.__xmpp.makeIqSet()
                dataElem = ET.Element('{%s}data' %XMLNS, sid=self.sid, seq=str(self.getNextOutSeqId()))
                dataElem.text = base64.b64encode(data)
                iq['to'] = self.otherPartyJid
                iq.setPayload(dataElem)
                response = iq.send(block=True, timeout=120, priority=2)
                if response == False or response.get('type') != 'result':
                    break
                self.__lastMessage = time.time()
        self.process = False
        self._closeStream()
        
    def _closeStream(self):
        '''
        This method is thread safe, and only callable once.  Use it to terminate
        the session with the other party
        '''
        with self.__closeStreamLock:
            if not self.streamClosed:
                self.streamClosed = True
                sendCloseStream(self.__xmpp, self.otherPartyJid, self.sid)
                self.__xmpp.event(STREAM_CLOSED_EVENT, {'sid': self.sid})
        
class InBandTransferException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)

class TooManySessionsException(InBandTransferException):
    def __init__(self, *args, **kwargs):
        InBandTransferException.__init__(self, *args, **kwargs)



    
        

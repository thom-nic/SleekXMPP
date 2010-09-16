'''
Created on Sep 3, 2010

@author: bbeggs
'''
import unittest
import logging
from xml.etree.cElementTree import XML, tostring
from tests.sleektest import TestSocket
from sleekxmpp import ClientXMPP
import sleekxmpp.plugins.xep_0096
from sleekxmpp.plugins import xep_0096
from sleekxmpp.plugins.xep_0047 import xep_0047
import time

class test_xep_0096(unittest.TestCase):
    def setUp(self):
        #logging.getLogger().setLevel(logging.DEBUG)
        self.xmpp = ClientXMPP('tester@localhost', 'test')
        self.xmpp.setSocket(TestSocket())
        self.xmpp.connect('localhost', 5222)
        self.xmpp.registerPlugin('xep_0047')
        self.xmpp.registerPlugin('xep_0096', pconfig={'maxSessions' : 2})
        self.xmpp.registerPlugin('xep_0030')
        self.xmpp.state.transition_ctx('connected','disconnected')
        self.xmpp.socket.recvData(self.xmpp.stream_header)
        self.xmpp.connectTCP = lambda a, b, c, d: True
        self.xmpp.startTLS = lambda: True
        self.xmpp.process(threaded=True)
        self.xmpp.socket.nextSent(timeout=0.1)
        self.xmpp.sessionstarted = True
        self.xmpp.authenticated = True
        
    def test_register_features(self):
        self.xmpp.plugin['xep_0096'].add_feature(MockFTMech.XMLNS, MockFTMech(), False)
    
    def test_SendRequest(self):
        sid = xep_0096.generateSid()
        iq = xep_0096.makeStreamOfferIQ(self.xmpp.makeIqSet(),
                                 'testuser2@localhost', 
                                 sid, 
                                 [xep_0047.XMLNS, MockFTMech.XMLNS], 
                                 'test.txt', 
                                 '12345', 
                                 'abcdefg', 
                                 fileDesc="this is the description")
        iq.send(priority=2, block=False)
        
        xml = self.xmpp.socket.nextSent(timeout=1)
        root = XML(xml)
        #verify the elements
        self.assertTrue(len(root.findall('.//{%s}si' %xep_0096.PROTOCOL_SI_XMLNS)) > 0) 
        self.assertTrue(len(root.findall('.//{%s}feature' %xep_0096.PROTOCOL_FEATURENEG_XMLNS)) > 0)
        self.assertTrue(len(root.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}option/{jabber:x:data}value')) == 2)
        #Verify the stream protocols
        for item in root.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}option/{jabber:x:data}value'):
            self.assertTrue(item.text == xep_0047.XMLNS or item.text == MockFTMech.XMLNS)
        #Verify the file info
        item = root.find('.//{http://jabber.org/protocol/si}si/{http://jabber.org/protocol/si/profile/file-transfer}file')
        self.assertTrue(item is not None)
        self.assertTrue(item.get('name') == 'test.txt')
        self.assertTrue(item.get('size') == '12345')
        self.assertTrue(item.get('hash') == 'abcdefg')
        #verify the sid
        item = root.find('.//{http://jabber.org/protocol/si}si')
        self.assertTrue(item is not None)
        self.assertTrue(item.get('id') == sid)
        
    def test_parseRequestXMLToDict(self):
        sid = xep_0096.generateSid()
        iq = xep_0096.makeStreamOfferIQ(self.xmpp.makeIqSet(),
                                 'testuser2@localhost', 
                                 sid, 
                                 [xep_0047.XMLNS, MockFTMech.XMLNS], 
                                 'test.txt', 
                                 '12345', 
                                 'abcdefg', 
                                 fileDesc="this is the description")
        
        xferInfo = xep_0096.parseRequestXMLToDict(iq.xml)
        self.assertTrue(xferInfo['filehash'] == 'abcdefg')
        self.assertTrue(xferInfo['filename'] == 'test.txt')
        self.assertTrue(len(xferInfo['protocols']) == 2)
        self.assertTrue(xferInfo['filesize'] == '12345')
        self.assertTrue(xferInfo['sid'] == sid)
        
        #self.xmpp.socket.recvData(tostring(iq.xml))  
        #time.sleep(1)
        #xml = self.xmpp.socket.nextSent() 
        
             
    def test_rejectRequest(self):
        self.xmpp.plugin['xep_0096'].acceptTransfers = False
        self.xmpp.plugin['xep_0096'].acceptTransferCallback = lambda x: False
        sid = xep_0096.generateSid()
        iq = xep_0096.makeStreamOfferIQ(self.xmpp.makeIqSet(),
                                 'testuser2@localhost', 
                                 sid, 
                                 [xep_0047.XMLNS, MockFTMech.XMLNS], 
                                 'test.txt', 
                                 '12345', 
                                 'abcdefg', 
                                 fileDesc="this is the description")
        self.xmpp.socket.recvData(tostring(iq.xml))  
        time.sleep(.5)
        xml = XML(self.xmpp.socket.nextSent())
        self.assertTrue(xml.get('type') == 'error')
        self.assertTrue(xml.find('.//error/{urn:ietf:params:xml:ns:xmpp-stanzas}text').text == 'Offer Declined')
        self.assertTrue(xml.find('.//error/').get('code')=='403')
        
    def test_rejectRequestTooManyTransfers(self):
        self.xmpp.plugin['xep_0096'].acceptTransfers = True
        self.xmpp.plugin['xep_0096'].acceptTransferCallback = lambda x: True
        self.xmpp.plugin['xep_0096'].maxSessions = 2
        mockFTMech = MockFTMech()
        mockFTMech.currentTransfers = {'1': 1, '2': 2, '3': 3, '4': 4}
        self.xmpp.plugin['xep_0096'].add_feature(MockFTMech.XMLNS, mockFTMech, False)
        sid = xep_0096.generateSid()
        iq = xep_0096.makeStreamOfferIQ(self.xmpp.makeIqSet(),
                                 'testuser2@localhost', 
                                 sid, 
                                 [xep_0047.XMLNS, MockFTMech.XMLNS], 
                                 'test.txt', 
                                 '12345', 
                                 'abcdefg', 
                                 fileDesc="this is the description")
        self.xmpp.socket.recvData(tostring(iq.xml))  
        time.sleep(.5)
        xml = XML(self.xmpp.socket.nextSent())
        self.assertTrue(xml.get('type') == 'error')
        self.assertTrue(xml.find('.//error/{urn:ietf:params:xml:ns:xmpp-stanzas}text').text == 'Offer Declined')
        self.assertTrue(xml.find('.//error/').get('code')=='403')
        
    def test_acceptRequest(self):
        self.xmpp.plugin['xep_0096'].acceptTransfers = True
        self.xmpp.plugin['xep_0096'].acceptTransferCallback = lambda x: True
        sid = xep_0096.generateSid()
        iq = xep_0096.makeStreamOfferIQ(self.xmpp.makeIqSet(),
                                 'testuser2@localhost', 
                                 sid, 
                                 [xep_0047.XMLNS, MockFTMech.XMLNS], 
                                 'test.txt', 
                                 '12345', 
                                 'abcdefg', 
                                 fileDesc="this is the description")
        self.xmpp.socket.recvData(tostring(iq.xml))  
        time.sleep(.5)
        xml = XML(self.xmpp.socket.nextSent())
        self.assertTrue(len(xml.findall('.//{%s}si' %xep_0096.PROTOCOL_SI_XMLNS)) > 0)
        self.assertTrue(len(xml.findall('.//{%s}feature' %xep_0096.PROTOCOL_FEATURENEG_XMLNS)) > 0)
        self.assertTrue(len(xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}value')) == 1)
        self.assertTrue(xml.find('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}value').text == xep_0047.XMLNS)
        print tostring(xml)
        
    def test_makeAcceptResultIQ(self):
        iq = xep_0096.makeAcceptResultIQ(self.xmpp.makeIqResult('12345'), 'testuser2@localhost', xep_0047.XMLNS)
        iq.send(priority=2, block=False)
        xml = self.xmpp.socket.nextSent(timeout=1)
        
        root = XML(xml)
        self.assertTrue(len(root.findall('.//{%s}si' %xep_0096.PROTOCOL_SI_XMLNS)) > 0)
        self.assertTrue(len(root.findall('.//{%s}feature' %xep_0096.PROTOCOL_FEATURENEG_XMLNS)) > 0)
        self.assertTrue(len(root.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}value')) == 1)
        self.assertTrue(root.find('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}value').text == xep_0047.XMLNS)
        
    def test_makeRejectStreamIQ(self):
        iq = xep_0096.makeRejectStreamIQ(self.xmpp.makeIqResult('12345'), 'testuser2@localhost')
        
        iq.send(priority=2, block=False)
        
        xml = self.xmpp.socket.nextSent(timeout=1)
        root = XML(xml)
        self.assertTrue(root.get('type') == 'error')
        self.assertTrue(root.find('.//error/{urn:ietf:params:xml:ns:xmpp-stanzas}text').text == 'Offer Declined')
        self.assertTrue(root.find('.//error/').get('code')=='403')
        
    def test_makeNoValidStreamsIQ(self):
        iq = xep_0096.makeNoValidStreamsIQ(self.xmpp.makeIqResult('12345'), 'testuser2@localhost')
        
        iq.send(priority=2, block=False)
        
        xml = self.xmpp.socket.nextSent(timeout=1)
        root = XML(xml)
        self.assertTrue(root.get('type') == 'error')
        self.assertTrue(root.find('.//error/').get('code')=='400')
        self.assertTrue(root.find('.//error/{urn:ietf:params:xml:ns:xmpp-stanzas}bad-request') is not None)
        self.assertTrue(root.find('.//error/{http://jabber.org/protocol/si}no-valid-streams') is not None)
        
    def test_makeProfileNotUnderstoodIQ(self):
        iq = xep_0096.makeProfileNotUnderstoodIQ(self.xmpp.makeIqResult('12345'), 'testuser2@localhost')
        
        iq.send(priority=2, block=False)
        
        xml = self.xmpp.socket.nextSent(timeout=1)
        root = XML(xml)
        self.assertTrue(root.get('type') == 'error')
        self.assertTrue(root.find('.//error/').get('code')=='400')
        self.assertTrue(root.find('.//error/{urn:ietf:params:xml:ns:xmpp-stanzas}bad-request') is not None)
        self.assertTrue(root.find('.//error/{http://jabber.org/protocol/si}bad-profile') is not None)
        
class MockFTMech(xep_0096.FileTransferProtocol):
    XMLNS = 'http://localhost/protocol'
    
    def __init__(self):
        self.currentTransfers = {}
    
    def sendFile(self, fileName, to, threaded=True):
        print('send file called... to: %s filename: %s threaded: %s' %(to, fileName, threaded))
    
    def getSessionStatus(self, sid):
        print('getSessionStatus called')
        
    def getSessionStatusAll(self):
        return self.currentTransfers
    
    def cancelSend(self, sid): 
        print('cancelSend called')
    
if __name__ == '__main__': unittest.main()
#suite = unittest.TestLoader().loadTestsFromTestCase(test_xep_0096)
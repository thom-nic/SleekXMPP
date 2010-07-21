import unittest
import time
from datetime import datetime
from xml.etree import cElementTree as ET

if __name__ == '__main__': 
	import sys, os
	sys.path.insert(0, os.getcwd())


from sleekxmpp.plugins import xep_0202

class test_xep_0202(unittest.TestCase):

	def set_up(self):
	    pass
	
	def test_time_element_to_xml(self):
		"Test TimeElement._to_xml"
		now = time.time()
		te = xep_0202.TimeElement(now)
		xml = te.to_xml()
		self.assertEquals( str(te),
		        '<ns0:time xmlns:ns0="urn:xmpp:time"><tzo>Z</tzo><utc>%sZ</utc></ns0:time>' %
		            datetime.isoformat(datetime.utcfromtimestamp(now)) )
		
	def test_time_element_constructor(self):
		"Test TimeElement.__init__"
		utc =  datetime.isoformat(datetime.utcfromtimestamp(time.time())) +'Z'
		te = xep_0202.TimeElement( utc )
		xml = te.to_xml()
		self.assertEquals( str(te),
		        '<ns0:time xmlns:ns0="urn:xmpp:time"><tzo>Z</tzo><utc>%s</utc></ns0:time>' %
		            utc )
	
	def test_time_element_constructor2(self):
		"Test TimeElement.__init__ with timezone offset."
		utc =  datetime.isoformat(datetime.utcfromtimestamp(time.time())) +'Z'
		te = xep_0202.TimeElement( utc, "-05:00" )
		xml = te.to_xml()
		self.assertEquals( str(te),
		       '<ns0:time xmlns:ns0="urn:xmpp:time"><tzo>-05:00</tzo><utc>%s</utc></ns0:time>' %
		            utc )


	def test_time_element_constructor_wo_ms(self):
		"Test TimeElement.__init__ with timestamp - milliseconds."
		utc =  datetime.isoformat(datetime.utcfromtimestamp(int(time.time()))) +'Z'
		self.assertEquals(utc.find('.'), -1) # ensure no milliseconds in timestamp.
		te = xep_0202.TimeElement( utc )
		xml = te.to_xml()
		self.assertEquals( str(te),
		       '<ns0:time xmlns:ns0="urn:xmpp:time"><tzo>Z</tzo><utc>%s</utc></ns0:time>' %
		            utc )

suite = unittest.TestLoader().loadTestsFromTestCase(test_xep_0202)
if __name__ == '__main__': unittest.main()

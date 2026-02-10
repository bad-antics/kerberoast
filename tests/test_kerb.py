import unittest,sys,os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"..","src"))
from kerberoast.core import SPNEnumerator,KerberoastDetector

class TestSPN(unittest.TestCase):
    def test_parse(self):
        s=SPNEnumerator()
        r=s.parse_spn("MSSQLSvc/sql.corp.local:1433")
        self.assertEqual(r["service"],"MSSQLSvc")
        self.assertEqual(r["port"],"1433")

class TestDetector(unittest.TestCase):
    def test_detection(self):
        d=KerberoastDetector()
        events=[{"user":"attacker"} for _ in range(20)]
        findings=d.analyze_events(events)
        self.assertGreater(len(findings),0)

if __name__=="__main__": unittest.main()

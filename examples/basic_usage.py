from kerberoast.core import SPNEnumerator,KerberoastDetector
s=SPNEnumerator()
for spn in ["MSSQLSvc/sql:1433","HTTP/web.corp.local","CIFS/file.corp.local"]:
    print(f"SPN: {spn} -> {s.parse_spn(spn)}")
d=KerberoastDetector()
print(f"\nMitigations:")
for m in d.recommend_mitigations(): print(f"  - {m}")

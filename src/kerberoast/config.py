"""Kerberoast Config"""
DOMAIN="CORP.LOCAL"
DC_IP="192.168.1.10"
ENCRYPTION_TYPES={"rc4":23,"aes128":17,"aes256":18}
SPN_QUERY_FILTER="(&(objectClass=user)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
OUTPUT_FORMAT="hashcat"
SAFE_MODE=True

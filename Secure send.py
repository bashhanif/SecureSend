
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,   # e or public exponent
    key_size=2048,   # minimum 2048 bit key
)

public_key = private_key.public_key()



#serialization , converting data into format that can be easily stored or transmitted rsa method 

pem_private = private_key.private_bytes(
    encoding= serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,   #pkcs8 allows for better encryption , standard format 
    encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')  #byte input password

)

#same thing but for public 
pem_public = public_key.public_bytes(    #main diff public_bytes 

    encoding= serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo

)

print("Private Key (PKCS#8):\n", pem_private.decode())   #testing 
print("Public Key (PEM):\n", pem_public.decode())    #testing

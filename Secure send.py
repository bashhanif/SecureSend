
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class RSAkeygen:
    def __init__(self, key_size=2048, public_exponent=65537):
        self.private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )



    def get_private_key_pem(self , password=None):  #password protects private key on our side
           
            encryption_algorithm = (
                serialization.BestAvailableEncryption(b'mypassword')
                if password
                else serialization.NoEncryption()    # if no password provided still pem encoded less secure 
            )
        
            return self.private_key.private_bytes(
                encoding= serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm = encryption_algorithm
            )
        

    def get_public_key_pem(self):
            return self.private_key.public_key().public_bytes(
                encoding= serialization.Encoding.PEM,
                format= serialization.PublicFormat.SubjectPublicKeyInfo,
            )
    
class RSAEncryptDecrypt:
    def __init__(self,public_key,private_key):
            self.public_key = public_key
            self.private_key = private_key

    
    







if __name__ == "__main__":
    

        #testing
        key_manager = RSAkeygen()
        password = b'1234bingus'  # Change to your desired password
        private_key_pem = key_manager.get_private_key_pem(password=password)
        public_key_pem = key_manager.get_public_key_pem()

        print("Private Key (PKCS#8):\n", private_key_pem.decode())
        print("Public Key (PEM):\n", public_key_pem.decode())





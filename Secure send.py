
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class RSAkeygen:
    def __init__(self, key_size=2048, public_exponent=65537):
        self.private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )



    def get_private_key_pem(self , password=None):  #password protects private key on our side
           
            encryption_algorithm = (
                serialization.BestAvailableEncryption(password.encode())
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

    

    def encryption(self, message):
          return self.public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  #using sha 256 hash type
                    algorithm=hashes.SHA256(),
                    label=None
            )
            )
                        
    def decrypt(self, encrypted_message):
          
          return self.private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                      mgf=padding.MGF1(algorithm=hashes.SHA256()),
                      algorithm=hashes.SHA256(),
                      label=None
                )
                
                
                )
          

    
          
    







if __name__ == "__main__":
    
    #testing encryption and decyrption features

    keygen = RSAkeygen()
    password = "mypassword"

    private_key_pem = keygen.get_private_key_pem(password=password)
    public_key_pem = keygen.get_public_key_pem()


    private_key = serialization.load_pem_private_key(private_key_pem, password=password.encode())
    public_key = serialization.load_pem_public_key(public_key_pem)


    rsa_cipher = RSAEncryptDecrypt(public_key=public_key, private_key=private_key)


    original_message = "hello secure send!"
    encrypted_message = rsa_cipher.encryption(original_message)

    print("Encrypted message:", encrypted_message)

    decrypted_message = rsa_cipher.decrypt(encrypted_message).decode()
    print("decrypted message:" , decrypted_message)


    if original_message == decrypted_message:
          print("test was successful")
    else:
          print("bruh that aint work lol")








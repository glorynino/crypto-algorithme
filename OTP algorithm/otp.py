import os 

#OTP encryption

def encryption(message):
    resultat=[]
    input_bytes=message.encode()
    key = os.urandom(len(input_bytes))
    #dans otp la key est generer aleatoirement pas "pseudo-aleatoire"
    for x,y in zip(input_bytes,key):
        resultat.append(x^y)
    
    return resultat,key


def decryption(resultat,key):
    #on fait "zip" pour reunir chaque element de "resultat" et "key" dans un seule ellement 
    #en gros resultat = [1,2,3] et key = [4,5,6] alors zip(resultat,key) = [(1,4),(2,5),(3,6)]
    message = []
    for x,y in zip(resultat,key): 
        message.append(x^y)
     
    return bytes(message).decode()  #obliger de faire bytes pour faire decode et le convertir en string  
    '''bytes([72, 105])  →  b"Hi"
       bytes([72, 105]).decode()  →  "Hi"
    '''
   

if __name__ == "__main__":
    message = "Hello World"
    print("Message: ",message)
    resultat,key = encryption(message)
    print("Encrypted: ",resultat)
    decrypted_message = decryption(resultat,key)
    print("Decrypted: ",decrypted_message)
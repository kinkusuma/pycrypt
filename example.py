import pycrypt

key = 'mkdaq-12/c'

pycrypt.encrypt(key=key,
                filepath='lorem.txt', 
                encrypted_content_filename='lorem_encrypted.txt')

pycrypt.decrypt(key=key, 
                filepath='Export/lorem_encrypted.txt',
                decrypted_content_filename='lorem_decrypted.txt')
        
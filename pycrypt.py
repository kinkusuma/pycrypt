import os
import random

class Pycrypt:
    def __init__(self):
        self.all_char = (
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 
            'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 
            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 
            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
            'Y', 'Z', '!', '}', '#', '$', '%', '&', '(', '~',
            ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', 
            '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', 
            '|', '"', ' ', "'", '\\', '\t', '\n', '\x0b', '\x0c',
        )
    
    def __export_textfile(self, content, filepath):
        if os.path.exists('Export') == False:
            os.makedirs('Export')
        filepath = 'Export/'+str(filepath)+'.txt'
        with open(filepath, 'w') as tf:
            tf.write(content)
            tf.close()

    def __load_textfile(self, filepath):
        with open(str(filepath), 'r') as tf:
            result = tf.read()
        return result

    def __generate_key(self):
        key = ''
        shuffled_all_char = [char for char in self.all_char[:-8]]
        random.shuffle(shuffled_all_char)
        for char in shuffled_all_char[0:10]:
            key += char
        return key

    def __generate_char_dict(self, key):
        seed = 0
        for char in key:
            idx = self.all_char.index(char)
            seed *= idx
        
        seed = int(str(seed)[:3])
        random.seed(seed)
            
        char_dict = {}
        for char in self.all_char:
            shuffled_all_char = [char for char in self.all_char[:-6]]
            random.shuffle(shuffled_all_char)
            
            char_pass = ''
            for i in shuffled_all_char[:5]:
                char_pass += i
                
            char_dict.setdefault(char,char_pass)
            seed = seed + seed
        return char_dict
        
            
    def encrypt(self, 
                key=None, 
                content=None,
                filepath=None, 
                export_encrypted_content=True,
                encrypted_content_filename=None,
                export_key=False,
                key_filename=None,
                print_result=False):
        
        if content == None and filepath == None:
            raise ValueError('You need fill the content or filepath')
            
        if key == None:
            print('Generating key..')
            key = self.__generate_key()
            print('Your key is:\n' + key + '\n')
        
        
        if len(key) > 10 or len(key) < 10:
            raise ValueError('Key have to 10 byte block')
        
        if filepath != None:
            content = self.__load_textfile(filepath)
            
        char_dict = self.__generate_char_dict(key)
        
        encrypted_content = ''
        for char in content:
                encrypted_content += char_dict[char]
                
        if print_result == True:
            print(encrypted_content)
            
        if export_key == True:
            if key_filename == None:
                key_filename = 'KEY'
            if '.txt' in key_filename:
                key_filename = key_filename[:-4]
            self.__export_textfile('Your key is '+key, key_filename)
            print('Your key saved at:', os.path.abspath(key_filename))
        
        if export_encrypted_content == True:
            print('Encryption success..')
            if encrypted_content_filename == None:
                encrypted_content_filename = 'ENCRYPT'
            if '.txt' in encrypted_content_filename:
                encrypted_content_filename = encrypted_content_filename[:-4]    
            self.__export_textfile(encrypted_content, encrypted_content_filename)
            print('File saved at:', os.path.abspath(encrypted_content_filename))
        else:
            print('The encrypted content:\n' + encrypted_content + '\n')
            
    
    def decrypt(self, 
                key=None, 
                content=None,
                filepath=None, 
                export_decrypted_content=True,
                decrypted_content_filename=None,
                print_result=False):
            
        if key == None:
            raise ValueError('Please fill the key')
            
        if len(key) > 10 or len(key) < 10:
            raise ValueError('Key have to 10 byte block')
        
        if content == None and filepath == None:
            raise ValueError('You need fill the content or filepath')
        
        if filepath != None:
            content = self.__load_textfile(filepath)
            
        char_dict = self.__generate_char_dict(key)
        
        content_chunk = [content[i:i+5] for i in range(0, len(content), 5)]
        decrypted_content = ''
        for chunk in content_chunk:
            for items in char_dict.items():
                if chunk == items[1]:
                    decrypted_content += items[0]
                    
        if print_result == True:
            print(decrypted_content)
        
        if export_decrypted_content == True:
            print('Decryption success..')
            if decrypted_content_filename == None:
                decrypted_content_filename = 'DECRYPT'
            if '.txt' in decrypted_content_filename:
                decrypted_content_filename = decrypted_content_filename[:-4]    
            self.__export_textfile(decrypted_content, decrypted_content_filename)
            print('File saved at:', os.path.abspath(decrypted_content_filename))
        else:
            print('The decrypted content:\n' + decrypted_content + '\n')
        
        
            
_run = Pycrypt()
encrypt = _run.encrypt
decrypt = _run.decrypt



def _test():
    with open('Export/test_content.txt', 'w') as tf:
        tf.write('Hello World!')
        tf.close()
        
    test_content = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'+"'"+'()*+,-./:;<=>?@[\]^_`{|}~ \t\n\x0b\x0c'
    test_key = '1234567890'
    test_content_path = 'Export/test_content.txt'
    
    encrypt(key=test_key, 
            content=test_content, 
            export_encrypted_content=True, 
            export_key=True)
        
    encrypt(filepath=test_content_path,
            export_encrypted_content=True,
            encrypted_content_filename='test_encrypt.txt',
            export_key=True, 
            key_filename='test_key.txt')
    
    if os.path.exists('Export/KEY.txt') == False:
        raise FileNotFoundError('file Export/KEY.txt not exist')
    if os.path.exists('Export/ENCRYPT.txt') == False:
        raise FileNotFoundError('file Export/ENCRYPT.txt not exist')
    if os.path.exists('Export/test_key.txt') == False:
        raise FileNotFoundError('file Export/test_key.txt not exist')
    if os.path.exists('Export/test_encrypt.txt') == False:
        raise FileNotFoundError('file Export/test_encrypt.txt not exist')
    
    with open('Export/KEY.txt', 'r') as key_file, open(
                'Export/ENCRYPT.txt', 'r') as encrypted_file, open(
                    'Export/test_key.txt', 'r') as second_key_file, open(
                        'Export/test_encrypt.txt', 'r') as second_encrypted_file:
        if test_key not in key_file.read():
            raise ValueError('key file not contain test key value')
        test_encrypt = encrypted_file.read()
        second_test_key = second_key_file.read()[-10:]
        second_test_encrypt = second_encrypted_file.read()
        
    decrypt(key=test_key, 
            content=test_encrypt, 
            export_decrypted_content=True)
    
    decrypt(key=second_test_key, 
            content=second_test_encrypt, 
            export_decrypted_content=True, 
            decrypted_content_filename='test_decrypt.txt')
    
    if os.path.exists('Export/DECRYPT.txt') == False:
        raise FileNotFoundError('file Export/DECRYPT.txt not exist')
    if os.path.exists('Export/test_decrypt.txt') == False:
        raise FileNotFoundError('file Export/test_decrypt.txt not exist') 
        
    with open('Export/DECRYPT.txt', 'r') as decrypted_file, open(
                'Export/test_decrypt.txt', 'r') as second_decrypted_file:
        if decrypted_file.read() != test_content:
            raise ValueError('decrypted method error')
        if second_decrypted_file.read() != 'Hello World!':
            raise ValueError('decrypted method error')
    
    

if __name__ == '__main__':
    _test()

        

        





        

        


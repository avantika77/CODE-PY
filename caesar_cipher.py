letters = 'abcdefghijklmnopqrstuvwxyz'
num_letters = len(letters)  # letter values in more than 26

def encrypt(plaintext, key):
    ciphertext = ''
    for letter in plaintext:
        letter = letter.lower()
        if not letter == ' ':
            index = letters.find(letter)
            if index == -1:
                ciphertext += letter
            else:
                new_index = (index + key) % num_letters  # use modulo to handle values greater than 26
                ciphertext += letters[new_index]
        else:
            ciphertext += ' '  # add space if the character is a space
    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ''
    for letter in ciphertext:
        letter = letter.lower()
        if not letter == ' ':
            index = letters.find(letter)
            if index == -1:
                plaintext += letter
            else:
                new_index = (index - key) % num_letters  # use modulo to handle values less than 0
                plaintext += letters[new_index]
        else:
            plaintext += ' '  # add space if the character is a space
    return plaintext

                    
'''def encrypt_decrypt(text,mode,key):
    result =''
    if mode== 'd':
      key =-key
    for letter in text:
        letter =letter.lower()
        if not letter ==' ':
            index =letters.find(letter)
            if index==-1:
                result+=letter
            else:
                new_index=index+key
                if new_index >= num_letters:
                    new_index -=num_lettters
                elif new_index < 0:
                    new_index+=num_letters
                    result+=letter[new_index]
                    return result  '''
                                       
#key=3

"""g-->j
j-->g
x-->c
c-->x """

print()
print('*** CAESAR CIPHER PROGRAM ***')
print()

print("DO YOU WANT TO ENCRYPT OR DECRYPT?")
user_input = input('e/d:').lower()  # user can enter in both cases
print()
if user_input == "e":
    print("ENCRYPTION MODE")
    print()
    key = int(input("Enter the key (1 to 26):"))  # 26 letters
    text = input("Enter the text:")
    ciphertext = encrypt(text, key)  # user input in middle
    print(f'CIPHERTEXT: {ciphertext}')

elif user_input == "d":
    print("DECRYPTION MODE")
    print()
    key = int(input("Enter the key (1 to 26):"))  # 26 letters
    text = input("Enter the text:")
    plaintext = decrypt(text, key)  # user input in middle
    print(f'DECRYPT: {plaintext}')

    
    
    

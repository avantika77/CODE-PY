#password generator
import random # module generate random numbers 
import string # module contain charcters - ASCII strings , digits and punctuations that will be use in choosing random characters for password
def generate_password(length): # function length
    characters = string.ascii_letters + string.digits + string.punctuation #all characters will be stored in characters variable of all type 
    password = ''.join(random.choice(characters) for _ in range(length)) # random.choice will randomly collect fom charcter
    #for i in range(length): this will be in provided lenght 
    #simply, this will choose randomly fom charcter variable  in given length by user 
    return password # return generated password

if __name__ == "__main__": #  Python idiom that is used to determine if the script is being run as the main program or if it is being imported as a module into another script.ensure that certain code blocks are only executed when the script is run directly, not when it is imported as a module.
    # you can also change __name__ to any other 
    # ex: if__w__=="main" better use name 
    try: #try-except block
        password_length = int(input("Enter the password length: ")) #user input for length 
        if password_length <= 0: #check length should not be <=0
            raise ValueError("Password length must be a positive integer.") #if <=0 raise value error
    except ValueError as e: #capture error in value e
        print(f"Invalid input: {e}") #use of  f-string
    else: #no error proceed
        generated_password = generate_password(password_length) #call the function of provided length
        print("Generated Password:", generated_password)#print the password 
        
        
#################################################################################################################
    
import random
password="abcdefghijklmnopqrstuvwxyzABCDEF1234567890&@#$%^&*"
length_pass=int(input("enter the length of the password:"))
a = " ".join(random.sample(password,length_pass))
print(f"Your password is:{a}")


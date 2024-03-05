# Cryptography---19CS412-classical-techqniques


# Caeser Cipher
Caeser Cipher using with different key values

# AIM:

To develop a simple C program to implement Caeser Cipher.

## DESIGN STEPS:

### Step 1:

Design of Caeser Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
``` def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def main():
    text = input("Enter the text to encrypt/decrypt: ")
    shift = int(input("Enter the shift value: "))

    choice = input("Enter 'E' for encryption or 'D' for decryption: ").upper()

    if choice == 'E':
        encrypted_text = caesar_cipher_encrypt(text, shift)
        print("Encrypted text:", encrypted_text)
    elif choice == 'D':
        decrypted_text = caesar_cipher_decrypt(text, shift)
        print("Decrypted text:", decrypted_text)
    else:
        print("Invalid choice. Please enter 'E' for encryption or 'D' for decryption.")

if __name__ == "__main__":
    main()
```
## OUTPUT:
<img width="344" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/eec32762-3017-4859-82ae-47a90d4de62d">
<img width="367" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/6d686e73-78ef-4b4a-a6ac-d17648cd509d">

## RESULT:
The program is executed successfully

---------------------------------

# PlayFair Cipher
Playfair Cipher using with different key values

# AIM:

To develop a simple C program to implement PlayFair Cipher.

## DESIGN STEPS:

### Step 1:

Design of PlayFair Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```def generate_playfair_matrix(key):
    key = key.replace(" ", "").upper()
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Excluding 'J' as per Playfair convention
    key_set = set(key)
    matrix = []

    # Create Playfair matrix
    for char in key + alphabet:
        if char not in key_set:
            key_set.add(char)

    key_list = list(key_set)

    for i in range(5):
        matrix.append(key_list[i*5:i*5+5])

    return matrix

def find_char_positions(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.replace(" ", "").upper()
    plaintext_pairs = []

    # Create pairs of letters from plaintext
    i = 0
    while i < len(plaintext):
        if i == len(plaintext) - 1 or plaintext[i] == plaintext[i + 1]:
            plaintext_pairs.append(plaintext[i] + 'X')
            i += 1
        else:
            plaintext_pairs.append(plaintext[i] + plaintext[i + 1])
            i += 2

    # Encrypt pairs
    ciphertext = ""
    for pair in plaintext_pairs:
        char1, char2 = pair[0], pair[1]
        row1, col1 = find_char_positions(matrix, char1)
        row2, col2 = find_char_positions(matrix, char2)

        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]

    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    ciphertext = ciphertext.replace(" ", "").upper()

    # Decrypt pairs
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_char_positions(matrix, char1)
        row2, col2 = find_char_positions(matrix, char2)

        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]

    # Remove any appended 'X' characters
    plaintext = plaintext.replace("X", "")

    return plaintext

def main():
    key = input("Enter the key: ")
    plaintext = input("Enter the plaintext: ")

    ciphertext = playfair_encrypt(plaintext, key)
    print("Encrypted Text:", ciphertext)

    decrypted_text = playfair_decrypt(ciphertext, key)
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
```
## OUTPUT:
<img width="331" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/5e593981-9d00-4b7d-b3d2-e90b4134f37c">

## RESULT:
The program is executed successfully


---------------------------

# Hill Cipher
Hill Cipher using with different key values

# AIM:

To develop a simple C program to implement Hill Cipher.

## DESIGN STEPS:

### Step 1:

Design of Hill Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```# *********
# -*- Made by VoxelPixel
# -*- For YouTube Tutorial
# -*- https://github.com/VoxelPixel
# -*- Support me on Patreon: https://www.patreon.com/voxelpixel
# *********

import sys
import numpy as np


def cipher_encryption():
    msg = input("Enter message: ").upper()
    msg = msg.replace(" ", "")

    # if message length is odd number, append 0 at the end
    len_chk = 0
    if len(msg) % 2 != 0:
        msg += "0"
        len_chk = 1

    # msg to matrices
    row = 2
    col = int(len(msg)/2)
    msg2d = np.zeros((row, col), dtype=int)

    itr1 = 0
    itr2 = 0
    for i in range(len(msg)):
        if i % 2 == 0:
            msg2d[0][itr1] = int(ord(msg[i])-65)
            itr1 += 1
        else:
            msg2d[1][itr2] = int(ord(msg[i])-65)
            itr2 += 1
    # for

    key = input("Enter 4 letter Key String: ").upper()
    key = key.replace(" ", "")

    # key to 2x2
    key2d = np.zeros((2, 2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3])-65
            itr3 += 1

    # checking validity of the key
    # finding determinant
    deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
    deter = deter % 26

    # finding multiplicative inverse
    mul_inv = -1
    for i in range(26):
        temp_inv = deter * i
        if temp_inv % 26 == 1:
            mul_inv = i
            break
        else:
            continue
    # for

    if mul_inv == -1:
        print("Invalid key")
        sys.exit()
    # if

    encryp_text = ""
    itr_count = int(len(msg)/2)
    if len_chk == 0:
        for i in range(itr_count):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            encryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            encryp_text += chr((temp2 % 26) + 65)
        # for
    else:
        for i in range(itr_count-1):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            encryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            encryp_text += chr((temp2 % 26) + 65)
        # for
    # if else

    print("Encrypted Text: {}".format(encryp_text))


def cipher_decryption():
    msg = input("Enter message: ").upper()
    msg = msg.replace(" ", "")

    # if message length is odd number, append 0 at the end
    len_chk = 0
    if len(msg) % 2 != 0:
        msg += "0"
        len_chk = 1

    # msg to matrices
    row = 2
    col = int(len(msg) / 2)
    msg2d = np.zeros((row, col), dtype=int)

    itr1 = 0
    itr2 = 0
    for i in range(len(msg)):
        if i % 2 == 0:
            msg2d[0][itr1] = int(ord(msg[i]) - 65)
            itr1 += 1
        else:
            msg2d[1][itr2] = int(ord(msg[i]) - 65)
            itr2 += 1
    # for

    key = input("Enter 4 letter Key String: ").upper()
    key = key.replace(" ", "")

    # key to 2x2
    key2d = np.zeros((2, 2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3]) - 65
            itr3 += 1
    # for

    # finding determinant
    deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
    deter = deter % 26

    # finding multiplicative inverse
    mul_inv = -1
    for i in range(26):
        temp_inv = deter * i
        if temp_inv % 26 == 1:
            mul_inv = i
            break
        else:
            continue
    # for

    # adjugate matrix
    # swapping
    key2d[0][0], key2d[1][1] = key2d[1][1], key2d[0][0]

    # changing signs
    key2d[0][1] *= -1
    key2d[1][0] *= -1

    key2d[0][1] = key2d[0][1] % 26
    key2d[1][0] = key2d[1][0] % 26

    # multiplying multiplicative inverse with adjugate matrix
    for i in range(2):
        for j in range(2):
            key2d[i][j] *= mul_inv

    # modulo
    for i in range(2):
        for j in range(2):
            key2d[i][j] = key2d[i][j] % 26

    # cipher to plain
    decryp_text = ""
    itr_count = int(len(msg) / 2)
    if len_chk == 0:
        for i in range(itr_count):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decryp_text += chr((temp2 % 26) + 65)
            # for
    else:
        for i in range(itr_count - 1):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decryp_text += chr((temp2 % 26) + 65)
            # for
    # if else

    print("Decrypted Text: {}".format(decryp_text))


def main():
    choice = int(input("1. Encryption\n2. Decryption\nChoose(1,2): "))
    if choice == 1:
        print("---Encryption---")
        cipher_encryption()
    elif choice == 2:
        print("---Decryption---")
        cipher_decryption()
    else:
        print("Invalid Choice")

if __name__ == "__main__":
    main()
```
          
 
  
## OUTPUT:
<img width="452" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/647caf44-5046-4f5d-96be-c6f2182894ec">

<img width="399" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/aa02dce8-fb95-41f3-b106-d4cbafca220b">

## RESULT:
The program is executed successfully

-------------------------------------------------

# Vigenere Cipher
Vigenere Cipher using with different key values

# AIM:

To develop a simple C program to implement Vigenere Cipher.

## DESIGN STEPS:

### Step 1:

Design of Vigenere Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```def vigenere_encrypt(plaintext, key):
    """
    Encrypts plaintext using the Vigenère cipher with the given key.
    """
    ciphertext = ""
    key_length = len(key)
    for i in range(len(plaintext)):
        shift = ord(key[i % key_length].upper()) - ord('A')
        if plaintext[i].isalpha():
            if plaintext[i].isupper():
                ciphertext += chr((ord(plaintext[i]) + shift - ord('A')) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(plaintext[i]) + shift - ord('a')) % 26 + ord('a'))
        else:
            ciphertext += plaintext[i]
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using the Vigenère cipher with the given key.
    """
    plaintext = ""
    key_length = len(key)
    for i in range(len(ciphertext)):
        shift = ord(key[i % key_length].upper()) - ord('A')
        if ciphertext[i].isalpha():
            if ciphertext[i].isupper():
                plaintext += chr((ord(ciphertext[i]) - shift - ord('A')) % 26 + ord('A'))
            else:
                plaintext += chr((ord(ciphertext[i]) - shift - ord('a')) % 26 + ord('a'))
        else:
            plaintext += ciphertext[i]
    return plaintext


# Example usage:
if __name__ == "__main__":
    plaintext = input("Enter plaintext")
    key = input("Enter key")

    # Encrypt
    encrypted_text = vigenere_encrypt(plaintext, key)
    print("Encrypted text:", encrypted_text)

    # Decrypt
    decrypted_text = vigenere_decrypt(encrypted_text, key)
    print("Decrypted text:", decrypted_text)
```
## OUTPUT:
<img width="221" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/b387ecc6-a54e-4829-9a17-731beb369974">


## RESULT:
The program is executed successfully

-----------------------------------------------------------------------

# Rail Fence Cipher
Rail Fence Cipher using with different key values

# AIM:

To develop a simple C program to implement Rail Fence Cipher.

## DESIGN STEPS:

### Step 1:

Design of Rail Fence Cipher algorithnm 

### Step 2:

Implementation using C or pyhton code

### Step 3:

Testing algorithm with different key values. 

## PROGRAM:
```# Python3 program to illustrate
# Rail Fence Cipher Encryption
# and Decryption

# function to encrypt a message
def encryptRailFence(text, key):
    # create the matrix to cipher
    # plain text key = rows ,
    # length(text) = columns
    # filling the rail matrix
    # to distinguish filled
    # spaces from blank ones
    rail = [['\n' for i in range(len(text))]
            for j in range(key)]

    # to find the direction
    dir_down = False
    row, col = 0, 0

    for i in range(len(text)):

        # check the direction of flow
        # reverse the direction if we've just
        # filled the top or bottom rail
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down

        # fill the corresponding alphabet
        rail[row][col] = text[i]
        col += 1

        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    # now we can construct the cipher
    # using the rail matrix
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return ("".join(result))


# This function receives cipher-text
# and key and returns the original
# text after decryption
def decryptRailFence(cipher, key):
    # create the matrix to cipher
    # plain text key = rows ,
    # length(text) = columns
    # filling the rail matrix to
    # distinguish filled spaces
    # from blank ones
    rail = [['\n' for i in range(len(cipher))]
            for j in range(key)]

    # to find the direction
    dir_down = None
    row, col = 0, 0

    # mark the places with '*'
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False

        # place the marker
        rail[row][col] = '*'
        col += 1

        # find the next row
        # using direction flag
        if dir_down:
            row += 1
        else:
            row -= 1

    # now we can construct the
    # fill the rail matrix
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if ((rail[i][j] == '*') and
                    (index < len(cipher))):
                rail[i][j] = cipher[index]
                index += 1

    # now read the matrix in
    # zig-zag manner to construct
    # the resultant text
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):

        # check the direction of flow
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False

        # place the marker
        if (rail[row][col] != '*'):
            result.append(rail[row][col])
            col += 1

        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    return ("".join(result))


# Driver code
if __name__ == "__main__":
    text=input("Enter text:")
    key=int(input("Enter key:"))
    print(encryptRailFence(text, key))


    # Now decryption of the
    # same cipher-text
    cipher=input("Enter cipher text:")
    key=int(input("Enter key:"))
    print(decryptRailFence(cipher, key))


# This code is contributed
# by Pratik Somwanshi
```
## OUTPUT:
<img width="231" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/69396606-d260-47b1-b066-9e5e9e0a3ac8">

## RESULT:
The program is executed successfully

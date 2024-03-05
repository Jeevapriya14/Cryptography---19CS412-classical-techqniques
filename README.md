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
```import numpy as np

def matrix_mod_inverse(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus) if gcd(det, modulus) == 1 else None
    if det_inv is None:
        return None
    adjugate = det * np.linalg.inv(matrix).T
    return (det_inv * adjugate) % modulus

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def hill_encrypt(plaintext, key):
    n = int(np.sqrt(len(key)))
    matrix = np.array([ord(char) - ord('A') for char in key]).reshape((n, n))
    plaintext = plaintext.upper().replace(" ", "").replace("\n", "")
    if len(plaintext) % n != 0:
        plaintext += 'X' * (n - len(plaintext) % n)
    ciphertext = ""
    for i in range(0, len(plaintext), n):
        block = np.array([ord(char) - ord('A') for char in plaintext[i:i+n]])
        encrypted_block = np.dot(matrix, block) % 26
        ciphertext += ''.join([chr(char + ord('A')) for char in encrypted_block])
    return ciphertext

def hill_decrypt(ciphertext, key):
    n = int(np.sqrt(len(key)))
    matrix = np.array([ord(char) - ord('A') for char in key]).reshape((n, n))
    inverse_matrix = matrix_mod_inverse(matrix, 26)
    if inverse_matrix is None:
        return "Inverse does not exist, unable to decrypt"
    plaintext = ""
    for i in range(0, len(ciphertext), n):
        block = np.array([ord(char) - ord('A') for char in ciphertext[i:i+n]])
        decrypted_block = np.dot(inverse_matrix, block) % 26
        plaintext += ''.join([chr(char + ord('A')) for char in decrypted_block])
    return plaintext

def main():
    key = input("Enter the key matrix (in uppercase, without spaces):\n")
    plaintext = input("Enter the plaintext:\n")
    mode = input("Enter 'E' for encryption or 'D' for decryption:\n").upper()

    if mode == 'E':
        encrypted_text = hill_encrypt(plaintext, key)
        print("Encrypted Text:", encrypted_text)
    elif mode == 'D':
        decrypted_text = hill_decrypt(plaintext, key)
        print("Decrypted Text:", decrypted_text)
    else:
        print("Invalid mode. Please enter 'E' or 'D'.")

if __name__ == "__main__":
    main()
```
## OUTPUT:
<img width="359" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/83db6f1b-cb44-4128-8252-e61f8e66f440">

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
```def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def matrix_mod_inverse(matrix, modulus):
    det = (
        matrix[0][0] * matrix[1][1] * matrix[2][2] +
        matrix[0][1] * matrix[1][2] * matrix[2][0] +
        matrix[0][2] * matrix[1][0] * matrix[2][1] -
        matrix[0][2] * matrix[1][1] * matrix[2][0] -
        matrix[0][0] * matrix[1][2] * matrix[2][1] -
        matrix[0][1] * matrix[1][0] * matrix[2][2]
    ) % modulus
    det_inv = pow(det, -1, modulus) if gcd(det, modulus) == 1 else None
    if det_inv is None:
        return None
    inverse_matrix = [
        [(matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]),
         (matrix[0][2] * matrix[2][1] - matrix[0][1] * matrix[2][2]),
         (matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1])],

        [(matrix[1][2] * matrix[2][0] - matrix[1][0] * matrix[2][2]),
         (matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0]),
         (matrix[0][2] * matrix[1][0] - matrix[0][0] * matrix[1][2])],

        [(matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]),
         (matrix[0][1] * matrix[2][0] - matrix[0][0] * matrix[2][1]),
         (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0])]
    ]
    for i in range(3):
        for j in range(3):
            inverse_matrix[i][j] *= det_inv
            inverse_matrix[i][j] %= modulus
    return inverse_matrix

def hill_encrypt(plaintext, key):
    n = int(len(key) ** 0.5)
    matrix = [list(map(ord, key[i:i+n])) for i in range(0, len(key), n)]
    plaintext = plaintext.upper().replace(" ", "").replace("\n", "")
    while len(plaintext) % n != 0:
        plaintext += 'X'
    ciphertext = ""
    for i in range(0, len(plaintext), n):
        block = [ord(char) - ord('A') for char in plaintext[i:i+n]]
        encrypted_block = [(matrix[0][0] * block[0] + matrix[0][1] * block[1] + matrix[0][2] * block[2]) % 26,
                           (matrix[1][0] * block[0] + matrix[1][1] * block[1] + matrix[1][2] * block[2]) % 26,
                           (matrix[2][0] * block[0] + matrix[2][1] * block[1] + matrix[2][2] * block[2]) % 26]
        ciphertext += ''.join([chr(char + ord('A')) for char in encrypted_block])
    return ciphertext

def hill_decrypt(ciphertext, key):
    n = int(len(key) ** 0.5)
    matrix = [list(map(ord, key[i:i+n])) for i in range(0, len(key), n)]
    inverse_matrix = matrix_mod_inverse(matrix, 26)
    if inverse_matrix is None:
        return "Inverse does not exist, unable to decrypt"
    plaintext = ""
    for i in range(0, len(ciphertext), n):
        block = [ord(char) - ord('A') for char in ciphertext[i:i+n]]
        decrypted_block = [(inverse_matrix[0][0] * block[0] + inverse_matrix[0][1] * block[1] + inverse_matrix[0][2] * block[2]) % 26,
                           (inverse_matrix[1][0] * block[0] + inverse_matrix[1][1] * block[1] + inverse_matrix[1][2] * block[2]) % 26,
                           (inverse_matrix[2][0] * block[0] + inverse_matrix[2][1] * block[1] + inverse_matrix[2][2] * block[2]) % 26]
        plaintext += ''.join([chr(char + ord('A')) for char in decrypted_block])
    return plaintext

def main():
    key = input("Enter the key matrix (10 characters in uppercase without spaces):\n")
    plaintext = input("Enter the plaintext:\n")

    if len(key) != 10 or not key.isalpha():
        print("Invalid key format. Please enter 10 characters in uppercase without spaces.")
        return

    encrypted_text = hill_encrypt(plaintext, key)
    decrypted_text = hill_decrypt(encrypted_text, key)

    print("Plaintext:", plaintext)
    print("Key:", key)
    print("Encrypted Text:", encrypted_text)
    print("Decrypted Text:", decrypted_text)

if __name__ == "__main__":
    main()
```
## OUTPUT:
<img width="449" alt="image" src="https://github.com/Jeevapriya14/Cryptography---19CS412-classical-techqniques/assets/121003043/c4e12756-f694-43ca-9bde-ceee2af95c53">

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

## OUTPUT:

## RESULT:
The program is executed successfully

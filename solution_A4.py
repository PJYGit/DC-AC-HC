# --------------------------
# Name: Jiayao Pang ID: 194174300
# CP460 (Fall 2019)
# Assignment 4
# --------------------------

import math
import string
import mod
import matrix
import utilities_A4


# ---------------------------------
# Q1: Modular Arithmetic Library #
# ---------------------------------

# solution is available in mod.py

# ---------------------------------
#     Q2: Decimation Cipher      #
# ---------------------------------
# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str,int)
# Return:       ciphertext (str)
# Description:  Encryption using Decimation Cipher
#               key is tuple (baseString,k)
#               Does not encrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key has no multiplicative inverse -->
#                   print error msg and return empty string
# -----------------------------------------------------------
def e_decimation(plaintext, key):
    # your code here
    if not isinstance(key, tuple):
        print('Error (e_decimation): Invalid key')
        return ''
    if not isinstance(key[0], str) or not isinstance(key[1], int):
        print('Error (e_decimation): Invalid key')
        return ''

    baseString = key[0]
    m = len(baseString)
    k = key[1]

    if not mod.has_mul_inv(k, m):
        print('Error (e_decimation): Invalid key')
        return ''

    ciphertext = ''

    for p in plaintext:
        if p.lower() in baseString:
            x = baseString.index(p.lower())
            y = mod.residue(k * x, m)
            cipherChar = baseString[y]
            ciphertext += cipherChar.upper() if p.isupper() else cipherChar
        else:
            ciphertext += p

    return ciphertext


# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str,int)
# Return:       plaintext (str)
# Description:  Decryption using Decimation Cipher
#               key is tuple (baseString,k)
#               Does not decrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key has no multiplicative inverse -->
#                   print error msg and return empty string
# -----------------------------------------------------------
def d_decimation(ciphertext, key):
    # your code here
    if not isinstance(key, tuple):
        print('Error (d_decimation): Invalid key')
        return ''
    if not isinstance(key[0], str) or not isinstance(key[1], int):
        print('Error (d_decimation): Invalid key')
        return ''

    baseString = key[0]
    m = len(baseString)
    k = key[1]

    if not mod.has_mul_inv(k, m):
        print('Error (d_decimation): Invalid key')
        return ''

    m_i_k = mod.mul_inv(k, m)

    plaintext = ''
    for c in ciphertext:
        if c.lower() in baseString:
            y = baseString.index(c.lower())
            x = mod.residue(m_i_k * y, m)
            plainChar = baseString[x]
            plaintext += plainChar.upper() if c.isupper() else plainChar
        else:
            plaintext += c

    return plaintext


# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext,key
# Description:  Cryptanalysis of Decimation Cipher
# -----------------------------------------------------------
def cryptanalysis_decimation(ciphertext):
    # your code here
    baseString = utilities_A4.get_baseString()
    length = len(baseString)
    dictList = utilities_A4.load_dictionary('engmix.txt')

    sub_baseString = []
    for j in range(25, length):
        sub_baseString.append(baseString[:j + 1])

    attempts = 0
    for n_s in sub_baseString:
        m_i_table = mod.mul_inv_table(len(n_s))

        for mi in m_i_table[0]:

            if m_i_table[1][mi] != 'NA':
                plaintext = d_decimation(ciphertext, (n_s, mi))
                attempts += 1

                if len(utilities_A4.remove_nonalpha(plaintext)) < len(plaintext) / 2:
                    continue

                if utilities_A4.is_plaintext(plaintext, dictList, 0.90):
                    print('key found after ' + str(attempts) + ' attempts')
                    return plaintext, (n_s, mi)

    return '', ''


# ---------------------------------
#      Q3: Affine Cipher         #
# ---------------------------------
# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str,[int,int])
# Return:       ciphertext (str)
# Description:  Encryption using Affine Cipher
#               key is tuple (baseString,[alpha,beta])
#               Does not encrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key can not be used for decryption
#                   print error msg and return empty string
# -----------------------------------------------------------
def e_affine(plaintext, key):
    # your code here
    if not isinstance(key, tuple):
        print('Error (e_affine): Invalid key')
        return ''
    if not isinstance(key[0], str) or not isinstance(key[1], list):
        print('Error (e_affine): Invalid key')
        return ''
    if not isinstance(key[1][0], int) or not isinstance(key[1][1], int):
        print('Error (e_affine): Invalid key')
        return ''

    baseString = key[0]
    m = len(baseString)
    alpha = key[1][0]
    beta = key[1][1]

    if not mod.has_mul_inv(alpha, m):
        print('Error (e_affine): Invalid key')
        return ''

    ciphertext = ''
    for p in plaintext:
        if p.lower() in baseString:
            x = baseString.index(p.lower())
            y = mod.residue(alpha * x + beta, m)
            cipherChar = baseString[y]
            ciphertext += cipherChar.upper() if p.isupper() else cipherChar
        else:
            ciphertext += p

    return ciphertext


# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str,[int,int])
# Return:       plaintext (str)
# Description:  Decryption using Affine Cipher
#               key is tuple (baseString,[alpha,beta])
#               Does not decrypt characters not in baseString
#               Case of letters should be preserved
# Errors:       if key can not be used for decryption
#                   print error msg and return empty string
# -----------------------------------------------------------
def d_affine(ciphertext, key):
    # your code here
    if not isinstance(key, tuple):
        print('Error (e_affine): Invalid key')
        return ''
    if not isinstance(key[0], str) or not isinstance(key[1], list):
        print('Error (e_affine): Invalid key')
        return ''
    if not isinstance(key[1][0], int) or not isinstance(key[1][1], int):
        print('Error (e_affine): Invalid key')
        return ''

    baseString = key[0]
    m = len(baseString)
    alpha = key[1][0]
    beta = key[1][1]

    if not mod.has_mul_inv(alpha, m):
        print('Error (e_affine): Invalid key')
        return ''

    m_i_alpha = mod.mul_inv(alpha, m)

    plaintext = ''
    for c in ciphertext:
        if c.lower() in baseString:
            y = baseString.index(c.lower())
            x = mod.residue((y - beta) * m_i_alpha, m)
            plainChar = baseString[x]
            plaintext += plainChar.upper() if c.isupper() else plainChar
        else:
            plaintext += c

    return plaintext


# -----------------------------------------------------------
# Parameters:   ciphertext (str)
# Return:       plaintext,key
# Description:  Cryptanalysis of Affine Cipher
# -----------------------------------------------------------
def cryptanalysis_affine(ciphertext):
    # your code here
    baseString = utilities_A4.get_baseString()
    length = len(baseString)
    dictList = utilities_A4.load_dictionary('engmix.txt')

    sub_baseString = []
    for j in range(25, length):
        sub_baseString.append(baseString[:j + 1])

    attempts = 0
    for n_s in sub_baseString:
        m_i_table = mod.mul_inv_table(len(n_s))

        for mi in m_i_table[0]:
            if m_i_table[1][mi] != 'NA':
                for beta in range(len(n_s)):
                    k = [mi, beta]
                    key = (n_s, k)
                    plaintext = d_affine(ciphertext, key)
                    attempts += 1

                    if len(utilities_A4.remove_nonalpha(plaintext)) < len(plaintext) / 2:
                        continue

                    if utilities_A4.is_plaintext(plaintext, dictList, 0.90):
                        print('key found after ' + str(attempts) + ' attempts')
                        return plaintext, key

    return '', ''


# ---------------------------------
#      Q4: Matrix Library        #
# ---------------------------------

# solution is available in matrix.py

# ---------------------------------
#       Q5: Hill Cipher          #
# ---------------------------------

# -----------------------------------------------------------
# Parameters:   plaintext (str)
#               key (str)
# Return:       ciphertext (str)
# Description:  Encryption using Hill Cipher, 2x2 (mod 26)
#               key is a string consisting of 4 characters
#                   if key is too short, make it a running key
#                   if key is too long, use first 4 characters
#               Encrypts only alphabet
#               Case of characters can be ignored --> cipher is upper case
#               If necessary pad with 'Q'
# Errors:       if key is not inveritble or if plaintext is empty
#                   print error msg and return empty string
# -----------------------------------------------------------
def e_hill(plaintext, key):
    # your code here
    if len(plaintext) == 0:
        print('Error(e_hill): invalid plaintext')
        return ''

    new_key = ''
    if len(key) > 4:
        new_key += key[:4]
    elif len(key) == 4:
        new_key += key
    else:
        new_key += key
        counter = 0
        while len(new_key) < 4:
            new_key += key[counter]
            counter += 1

    baseString = utilities_A4.get_lower()

    key_matrix = matrix.new_matrix(2, 2, 0)
    count = 0
    for i in range(2):
        for j in range(2):
            key_matrix[i][j] = baseString.index(new_key[count].lower())
            count += 1

    if mod.gcd(matrix.det(key_matrix), 26) != 1:
        print('Error(e_hill): key is not invertible')
        return ''

    ciphertext = ''
    non_alpha = utilities_A4.get_nonalpha(plaintext)
    blocks = utilities_A4.text_to_blocks(utilities_A4.remove_nonalpha(plaintext), 2)
    while len(blocks[-1]) != 2:
        blocks[-1] += 'Q'

    for block in blocks:
        block_m = matrix.new_matrix(2, 1, 0)
        block_m[0][0] = baseString.index(block[0].lower())
        block_m[1][0] = baseString.index(block[1].lower())

        result_m = matrix.matrix_mod(matrix.mul(key_matrix, block_m), 26)

        ciphertext += baseString[result_m[0][0]].upper()
        ciphertext += baseString[result_m[1][0]].upper()

    ciphertext = utilities_A4.insert_nonalpha(ciphertext, non_alpha)

    return ciphertext


# -----------------------------------------------------------
# Parameters:   ciphertext (str)
#               key (str)
# Return:       plaintext (str)
# Description:  Decryption using Hill Cipher, 2x2 (mod 26)
#               key is a string consisting of 4 characters
#                   if key is too short, make it a running key
#                   if key is too long, use first 4 characters
#               Decrypts only alphabet
#               Case of characters can be ignored --> plain is lower case
#               Remove padding of q's
# Errors:       if key is not inveritble or if ciphertext is empty
#                   print error msg and return empty string
# -----------------------------------------------------------
def d_hill(ciphertext, key):
    # your code here
    if len(ciphertext) == 0:
        print('Error(d_hill): invalid ciphertext')
        return ''

    new_key = ''
    if len(key) > 4:
        new_key += key[:4]
    elif len(key) == 4:
        new_key += key
    else:
        new_key += key
        counter = 0
        while len(new_key) < 4:
            new_key += key[counter]
            counter += 1

    baseString = utilities_A4.get_lower()

    key_matrix = matrix.new_matrix(2, 2, 0)
    count = 0
    for i in range(2):
        for j in range(2):
            key_matrix[i][j] = baseString.index(new_key[count].lower())
            count += 1

    if mod.gcd(matrix.det(key_matrix), 26) != 1:
        print('Error(d_hill): key is not invertible')
        return ''

    inverse_key_matrix = matrix.inverse(key_matrix, 26)

    plaintext = ''
    non_alpha = utilities_A4.get_nonalpha(ciphertext)
    blocks = utilities_A4.text_to_blocks(utilities_A4.remove_nonalpha(ciphertext), 2)

    for block in blocks:
        block_m = matrix.new_matrix(2, 1, 0)
        block_m[0][0] = baseString.index(block[0].lower())
        block_m[1][0] = baseString.index(block[1].lower())

        result_m = matrix.matrix_mod(matrix.mul(inverse_key_matrix, block_m), 26)

        plaintext += baseString[result_m[0][0]].lower()
        plaintext += baseString[result_m[1][0]].lower()

    plaintext = utilities_A4.insert_nonalpha(plaintext, non_alpha)
    while plaintext[-1] == 'q':
        plaintext = plaintext[:-1]

    return plaintext

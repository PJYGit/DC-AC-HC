# --------------------------
# Name: Jiayao Pang ID: 194174300
# CP460 (Fall 2019)
# Assignment 4
# --------------------------

import math
import string
import mod


# -----------------------------------------------------------
# Parameters:   A (any input)
# Return:       True/False
# Description:  checks if the given input is a valid vector
#               A valid vector is a list in which all elements are integers
#               An empty list is a valid vector
# Errors:       None
# -----------------------------------------------------------
def is_vector(A):
    # your code here
    if not isinstance(A, list):
        return False
    if len(A) == 0:
        return True
    for element in A:
        if not isinstance(element, int):
            return False
    return True


# -----------------------------------------------------------
# Parameters:   A (any input)
# Return:       True/False
# Description:  checks if the given input is a valid matrix
#               A matrix is a list in which all elements are valid vectors of equal size
#               Any valid vector is also a valid matrix
# Errors:       None
# -----------------------------------------------------------
def is_matrix(A):
    # your code here
    if not isinstance(A, list):
        return False
    if is_vector(A):
        return True
    for e in A:
        if not is_vector(e):
            return False
    size = len(A[0])
    for ele in A:
        if len(ele) != size:
            return False
    return True


# -----------------------------------------------------------
# Parameters:   A (a matrix)
# Return:       None
# Description:  Prints a given matrix, each row on a separate line
# Errors:       If A not a matrix --> print 'Error (print_matrix): Invalid input'
# -----------------------------------------------------------
def print_matrix(A):
    # your code here
    if not is_matrix(A):
        print('Error (print_matrix): Invalid input')
        return
    if is_vector(A):
        print(A)
        return

    for e in A:
        print(e)

    return


# -----------------------------------------------------------
# Parameters:   A (a matrix)
# Return:       number of rows (int)
# Description:  Returns number of rows in a given matrix
# Examples:     [5,3,2] --> 1
#               [] --> 0
#               [[1,2],[3,4],[5,6]] --> 3
# Errors:       If A not a matrix -->
#                   return 'Error (get_rowCount): invalid input'
# -----------------------------------------------------------
def get_rowCount(A):
    # your code here
    if not is_matrix(A):
        return 'Error (get_rowCount): invalid input'
    if is_vector(A):
        if len(A) == 0:
            return 0
        else:
            return 1
    return len(A)


# -----------------------------------------------------------
# Parameters:   A (a matrix)
# Return:       number of columns (int)
# Description:  Returns number of columns in a given matrix
# Examples:     [5,3,2] --> 3
#               [] --> 0
#               [[1,2],[3,4],[5,6]] --> 2
# Errors:       If A not a matrix -->
#                   return 'Error (get_columnCount): invalid input'
# -----------------------------------------------------------
def get_columnCount(A):
    # your code here
    if not is_matrix(A):
        return 'Error (get_columnCount): invalid input'
    if is_vector(A):
        return len(A)
    return len(A[0])


# -----------------------------------------------------------
# Parameters:   A (a matrix)
# Return:       [number of rows (int), number of columns(int)]
# Description:  Returns number size of matrix [rxc]
# Examples:     [5,3,2] --> [1,3]
#               [] --> [0,0]
#               [[1,2],[3,4],[5,6]] --> [3,2]
# Errors:       If A not a matrix -->
#                   return 'Error (get_size): invalid input'
# -----------------------------------------------------------
def get_size(A):
    # your code here
    if not is_matrix(A):
        return 'Error (get_size): invalid input'
    return [get_rowCount(A), get_columnCount(A)]


# -----------------------------------------------------------
# Parameters:   A (any input)
# Return:       True/False
# Description:  Checks if given input is a valid square matrix
# Examples:     [] --> True
#               [10] --> True
#               [[1,2],[3,4]] --> True
#               [[1,2],[3,4],[5,6]] --> False
# Errors:       None
# -----------------------------------------------------------
def is_square(A):
    # your code here
    if not is_matrix(A):
        return False
    if get_rowCount(A) != get_columnCount(A):
        return False
    return True


# -----------------------------------------------------------
# Parameters:   A (a matrix)
#               i (row number)
# Return:       row (list)
# Description:  Returns the ith row of given matrix
# Examples:     ([],0) --> Error
#               ([10],0) --> [10]
#               ([[1,2],[3,4]],0) --> [1,2]
# Errors:       If given matrix is empty or not a valid matrix -->
#                   return 'Error (get_row): invalid input matrix'
#               If i is outside the range [0,#rows -1] -->
#                   return 'Error (get_row): invalid row number'
# -----------------------------------------------------------
def get_row(A, i):
    # your code here
    if not is_matrix(A):
        return 'Error (get_row): invalid input matrix'
    if get_rowCount(A) == 0:
        return 'Error (get_row): invalid input matrix'
    if i >= get_rowCount(A) or i < 0:
        return 'Error (get_row): invalid row number'

    if get_rowCount(A) == 1:
        return A

    return A[i]


# -----------------------------------------------------------
# Parameters:   A (a matrix)
#               j (column number)
# Return:       column (list)
# Description:  Returns the jth column of given matrix
# Examples:     ([],0) --> Error
#               ([10],0) --> [10]
#               ([[1], [2]],0) --> [[1], [2]]
#               ([[1,2],[3,4]],1) --> [2,4]
# Errors:       If given matrix is empty or not a valid matrix -->
#                   return 'Error (get_column): invalid input matrix'
#               If i is outside the range [0,#rows -1] -->
#                   return 'Error (get_column): invalid column number'
# -----------------------------------------------------------
def get_column(A, j):
    # your code here
    if not is_matrix(A):
        return 'Error (get_column): invalid input matrix'
    if get_columnCount(A) == 0:
        return 'Error (get_column): invalid input matrix'
    if j >= get_columnCount(A) or j < 0:
        return 'Error (get_column): invalid column number'

    if get_rowCount(A) == 1:
        return [[A[j]]]

    c_temp = []
    for e in A:
        c_temp.append([e[j]])

    return c_temp


# -----------------------------------------------------------
# Parameters:   A (a matrix)
#               i (row number)
#               j (column number)
# Return:       element
# Description:  Returns element (i,j) of the given matrix
# Errors:       If given matrix is empty or not a valid matrix -->
#                   return 'Error (get_element): invalid input matrix'
#               If i or j is outside matrix range -->
#                   return 'Error (get_element): invalid element position'
# -----------------------------------------------------------
def get_element(A, i, j):
    # your code here
    if not is_matrix(A):
        return 'Error (get_element): invalid input matrix'
    if get_columnCount(A) == 0:
        return 'Error (get_element): invalid input matrix'
    if j >= get_columnCount(A) or j < 0 or i >= get_rowCount(A) or i < 0:
        return 'Error (get_element): invalid element position'

    if len(A) == 1:
        return A[j]

    return A[i][j]


# -----------------------------------------------------------
# Parameters:   r: #rows (int)
#               c: #columns (int)
#               pad (int)
# Return:       matrix
# Description:  Create an empty matrix of size r x c
#               All elements are initialized to integer pad
# Error:        r and c should be positive integers
#               (except the following which is valid 0x0 --> [])
#                   return 'Error (new_matrix): invalid size'
#               pad should be an integer
#                   return 'Error (new_matrix): invalid pad'
# -----------------------------------------------------------
def new_matrix(r, c, pad):
    # your code here
    if not isinstance(r, int) or not isinstance(c, int):
        return 'Error (new_matrix): invalid size'
    if r == 0 and c == 0:
        return []
    if r <= 0 or c <= 0:
        return 'Error (new_matrix): invalid size'
    if not isinstance(pad, int):
        return 'Error (new_matrix): invalid pad'

    if r == 1:
        temp = []
        for i in range(c):
            temp.append(pad)
        return temp

    return [[pad] * c for i in range(r)]


# -----------------------------------------------------------
# Parameters:   size (int)
# Return:       square matrix (identity matrix)
# Description:  returns the identity matrix of size: [size x size]
# Examples:     0 --> Error
#               1 --> [1]
#               2 --> [[1,0],[0,1]]
# Errors        size should be a positive integer
#                   return 'Error (get_I): invalid size'
# -----------------------------------------------------------
def get_I(size):
    # your code here
    if not isinstance(size, int):
        return 'Error (get_I): invalid size'
    if size <= 0:
        return 'Error (get_I): invalid size'

    if size == 1:
        return [1]

    matrix = new_matrix(size, size, 0)

    for i in range(size):
        matrix[i][i] = 1

    return matrix


# -----------------------------------------------------------
# Parameters:   A (any input)
# Return:       True/False
# Description:  Checks if given input is a valid identity matrix
# -----------------------------------------------------------
def is_identity(A):
    # your code here
    if not is_matrix(A):
        return False
    if not is_square(A):
        return False

    if len(A) == 1:
        if A[0] != 1:
            return False
        else:
            return True

    for i in range(len(A)):
        for j in range(len(A)):
            if i == j and A[i][j] != 1:
                return False
            if i != j and A[i][j] != 0:
                return False

    return True


# -----------------------------------------------------------
# Parameters:   c (int)
#               A (matrix)
# Return:       a new matrix which is the result of cA
# Description:  Performs scalar multiplication of constant c with matrix A
# Errors:       if A is empty or not a valid matrix or c is not an inger:
#                   return 'Error(scalar_mul): invalid input'
# -----------------------------------------------------------
def scalar_mul(c, A):
    # your code here
    if not is_matrix(A):
        return 'Error(scalar_mul): invalid input'
    if get_rowCount(A) == 0:
        return 'Error(scalar_mul): invalid input'
    if not isinstance(c, int):
        return 'Error(scalar_mul): invalid input'

    C = new_matrix(get_rowCount(A), get_columnCount(A), 0)

    if get_rowCount(A) == 1:
        for i in range(len(A)):
            C[i] = A[i] * c
    else:
        for i in range(len(A)):
            for j in range(len(A[0])):
                C[i][j] = A[i][j] * c

    return C


# -----------------------------------------------------------
# Parameters:   A (matrix)
#               B (matrix)
# Return:       a new matrix which is the result of AxB
# Description:  Performs cross multiplication of matrix A and matrix B
# Errors:       if eithr A or B or both is empty matrix nor not a valid matrix
#                   return 'Error(mul): invalid input'
#               if size mismatch:
#                   return 'Error(mul): size mismatch'
# -----------------------------------------------------------
def mul(A, B):
    # your code here
    if not is_matrix(A) or not is_matrix(B):
        return 'Error(mul): invalid input'
    if get_rowCount(A) == 0 or get_rowCount(B) == 0:
        return 'Error(mul): invalid input'
    if get_columnCount(A) != get_rowCount(B):
        return 'Error(mul): size mismatch'

    C = new_matrix(get_rowCount(A), get_columnCount(B), 0)

    for i in range(get_rowCount(A)):
        row = get_row(A, i)
        for j in range(get_columnCount(B)):
            column = get_column(B, j)

            sum = 0
            for counter in range(len(row)):
                sum += (row[counter] * column[counter][0])

            if get_rowCount(A) == 1:
                C[j] = sum
            else:
                C[i][j] = sum

    return C


# -----------------------------------------------------------
# Parameters:   A (matrix)
#               m (int)
# Return:       A` (matrix)
# Description:  Returns matrix A such that each element is the 
#               residue value in mode m
# Errors:       if A is empty matrix or not a valid matrix
#                   return 'Error(matrix_mod): invalid input'
#               if m is not a positive integer:
#                   return 'Error(matrix_mod): invalid mod'
# -----------------------------------------------------------
def matrix_mod(A, m):
    # your code here
    if not is_matrix(A):
        return 'Error(matrix_mod): invalid input'
    if get_rowCount(A) == 0:
        return 'Error(matrix_mod): invalid input'
    if not isinstance(m, int) or m <= 0:
        return 'Error(matrix_mod): invalid mod'

    C = new_matrix(get_rowCount(A), get_columnCount(A), 0)

    if get_rowCount(A) == 1:
        for i in range(len(A)):
            C[i] = mod.residue(A[i], m)
    else:
        for i in range(len(A)):
            for j in range(len(A[0])):
                C[i][j] = mod.residue(A[i][j], m)

    return C


# -----------------------------------------------------------
# Parameters:   A (matrix)
# Return:       determinant of matrix A (int)
# Description:  Returns the determinant of a 2x2 matrix
# Errors:       if A is empty matrix nor not a valid square matrix
#                   return 'Error(det): invalid input'
#               if A is square matrix of size other than 2x2
#                   return 'Error(det): Unsupported matrix size'
# -----------------------------------------------------------
def det(A):
    # your code here
    if not is_matrix(A) or not is_square(A):
        return 'Error(det): invalid input'
    if get_rowCount(A) == 0:
        return 'Error(det): invalid input'
    if get_rowCount(A) != 2:
        return 'Error(det): Unsupported matrix size'
    return A[0][0] * A[1][1] - A[0][1] * A[1][0]


# -----------------------------------------------------------
# Parameters:   A (matrix)
#               m (int)
# Return:       a new matrix which is the inverse of A mode m
# Description:  Returns the inverse of a 2x2 matrix in mode m
# Errors:       if A is empty matrix or not a valid matrix
#                   return 'Error(inverse): invalid input'
#               if A is not a square matrix or a matrix of 2x2 with no inverse:
#                   return 'Error(inverse): matrix is not invertible'
#               if A is a square matrix of size other than 2x2
#                   return 'Error(inverse): Unsupported matrix size'
#               if m is not a positive integer:
#                   return 'Error(inverse): invalid mod'
# -----------------------------------------------------------
def inverse(A, m):
    # your code here
    if not isinstance(m, int) or m <= 0:
        return 'Error(inverse): invalid mod'

    if not is_matrix(A):
        return 'Error(inverse): invalid input'
    if get_rowCount(A) == 0:
        return 'Error(inverse): invalid input'

    if not is_square(A):
        return 'Error(inverse): matrix is not invertible'
    else:
        if get_rowCount(A) == 2:
            if mod.gcd(det(A), m) != 1:
                return 'Error(inverse): matrix is not invertible'
        else:
            return 'Error(inverse): Unsupported matrix size'

    delta = mod.residue(det(A), m)
    m_i_delta = mod.mul_inv(delta, m)

    new = new_matrix(2, 2, 0)
    new[0][0] = A[1][1]
    new[0][1] = 0 - A[0][1]
    new[1][0] = 0 - A[1][0]
    new[1][1] = A[0][0]

    return matrix_mod(scalar_mul(m_i_delta, new), m)

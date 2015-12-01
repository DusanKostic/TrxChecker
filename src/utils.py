import io
import random
import hashlib
from sage.all import *

# Miller-Rabin primality test
# def is_probable_prime(n, k = 25):

#     assert n >= 2, "Error in is_probable_prime: input (%d) is < 2" % n

#     # First check if n is divisible by any of the prime numbers < 1000
#     low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
#                   59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
#                   127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
#                   191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
#                   257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
#                   331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
#                   401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
#                   467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
#                   563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
#                   631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
#                   709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
#                   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
#                   877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
#                   967, 971, 977, 983, 991, 997]

#     for prime in low_primes:
#         if (n % prime == 0):
#             return False

#     # Perform the real Miller-Rabin test
#     s = 0
#     d = n - 1
#     while True:
#         quotient, remainder = divmod(d, 2)
#         if remainder == 1:
#             break
#         s += 1
#         d = quotient

#     # test the base a to see if it is a witness for the compositeness of n
#     def try_composite(a):
#         if pow(a, d, n) == 1:
#             return False
#         for i in range(s):
#             if pow(a, 2**i * d, n) == n-1:
#                 return False
#         return True # n is definitely composite

#     for i in range(k):
#         a = random.randrange(2, n)
#         if try_composite(a):
#             return False
 
#     return True # no base tested showed n as composite

def next_prime_3_mod_4(start):
    p = start + 1
    while (p % 4) != 3:
        p = p + 1

    while True:
        if is_pseudoprime(p):
            return p
        else:
            p += 4

# Checks if given number x is a quadratic residue modulo p
def is_quadratic_residue(x, modulus):

    exp = (modulus - 1) / 2
    res = pow(x, exp, modulus)
    return res == 1

# Wrappers for sha hashing functions so that it is easy to change
# the implementation used (current is sha from python's hashlib).
def hash_sha512(input):

    if isinstance(input, str):
        input_enc = input.encode('ascii')
    else:
        input_enc = input

    return hashlib.sha512(input_enc).hexdigest()

def hash_sha384(input):

    if isinstance(input, str):
        input_enc = input.encode('ascii')
    else:
        input_enc = input

    return hashlib.sha384(input_enc).hexdigest()

def hash_sha256(input):

    if isinstance(input, str):
        input_enc = input.encode('ascii')
    else:
        input_enc = input

    return hashlib.sha256(input_enc).hexdigest()

def hash_sha2k(input, k):

    if k == 128:
        return hash_sha256(input)
    elif k == 192:
        return hash_sha384(input)
    elif k == 256:
        return hash_sha512(input)
    else:
        return None

def read_binary_file(file_path):

    data = []

    with io.open(file_path, mode = "rb") as f:
        byte = f.read(1)
        while byte:
            data.append(byte)
            byte = f.read(1)

    return data

def read_text_file(file_path):

    data = []

    with io.open(file_path, "r", encoding='ascii') as f:
        byte = f.read(1)
        while byte != "":
            data.append(byte)
            byte = f.read(1)

    return data

# Creates hex value of given integer x,
# but strips prefix '0x' and suffix 'L' which is added sometimes by python
def hex_strip(x):

    res = hex(x)[2:]
    if res[-1] == 'L':
        res = res[:-1]

    return res
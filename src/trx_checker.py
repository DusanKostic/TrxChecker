import os
import io
import sys
import math
import random
import hashlib
import utils
import time
import multiprocessing
from sage.all import *
import argparse

# Absolute path of the directory of this file
FILE_DIR = os.path.dirname(os.path.abspath(__file__))

# Directory of the repository
REPO_DIR = os.path.join(FILE_DIR, "..")

# Directory with data for all curves
# Every curve should have its own directory inside this one
CURVES_DATA_DIR = os.path.join(REPO_DIR, "curve_parameters")

# Tags which could identify needed files (raw_data, tweets, image file)
TAG_RAW_DATA_FILE = 'raw_data'
TAG_IMAGE_FILE    = '.jpg'
TAG_TWEETS_FILE   = 'tweets'
TAG_REJECTED_FILE = 'rejected_curves'

# Default output file name
DEF_OUTPUT_FILE = "trx_checker_out.txt"

class TrxChecker:

    sloth_unicorn_gen = None
    curve_gen         = None

    # TrxChecker initialized (all needed files exist)
    initialized   = False

    # Paths to files
    curve_param_dir   = None
    tweets_filepath   = None
    image_filepath    = None
    rawdata_filepath  = None
    output_filepath   = None
    rejected_filepath = None

    _tag_sloth_hash   = 'T3_SLOTH_HASH'
    _tag_sloth_comm   = 'T2_COMMITMENT'
    _tag_sloth_witn   = 'T3_WITNESS'

    _tag_prime_p      = 'T4_PARAMETER_P'
    _tag_coeff_a      = 'T4_PARAMETER_A'
    _tag_coeff_b      = 'T4_PARAMETER_B'
    _tag_cardinality  = 'T4_PARAMETER_ORDER'
    _tag_point_x      = 'T4_PARAMETER_COORD_X'
    _tag_point_y      = 'T4_PARAMETER_COORD_Y'

    def __init__(self, dir_name, out_file_name=DEF_OUTPUT_FILE):

        ok = self.generate_file_paths(dir_name, out_file_name)
        if not ok:            
            raise Exception("Error generating file paths in TrxChecker")

        self.sloth_unicorn_gen = SlothUnicornGenerator(self.tweets_filepath,
                                                       self.image_filepath)

        self.curve_gen = CurveGenerator(self.rawdata_filepath)

        self.initialized = True


    def check_trx(self, skip_sloth=False, skip_curve=False, use_rej=False):

        if not self.initialized:
            print ("TrxChecker is not initialized")
            return

        if not skip_sloth:
            self.check_sloth_unicorn()

        if not skip_curve:
            self.check_curve_gen(use_rej)

    def check_sloth_unicorn(self):

        with open(self.rawdata_filepath, 'r') as f:
            line = f.readline()
            while line:
                if self._tag_sloth_hash in line:
                    sloth_hash_exp = line.split('=')[1].rstrip()
                elif self._tag_sloth_comm in line:
                    sloth_comm_exp = line.split('=')[1].rstrip()
                elif self._tag_sloth_witn in line:
                    sloth_witn_exp = line.split('=')[1].rstrip()

                line = f.readline()

        start = time.time()

        self.sloth_unicorn_gen.verify(sloth_comm_exp,
                                      sloth_hash_exp,
                                      sloth_witn_exp)

        runtime = time.time() - start

        with open(self.output_filepath, 'w') as output_file:
                            
            ver = self.sloth_unicorn_gen.verification
            if ver == self.sloth_unicorn_gen.ALL_PASSED:
                output_file.write("\nSlothUnicorn checker: PASSED\n")
                output_file.write("\nRuntime: " + str(runtime))
                return
            else:
                output_file.write("\nSlothUnicorn checker: FAILED\n")

            if ver == self.sloth_unicorn_gen.COMMIT_FAIL:
                sloth_comm = self.sloth_unicorn_gen.get_sloth_commitment()                    
                output_file.write("\n  Commitment check: failed")
                output_file.write("\n    Expected commitment   =" + sloth_comm_exp)
                output_file.write("\n    Calculated commitment =" + sloth_comm)
            elif ver == self.sloth_unicorn_gen.WITNES_FAIL:
                sloth_witn = self.sloth_unicorn_gen.get_sloth_witness()
                output_file.write("\n  Commitment check: passed")
                output_file.write("\n  Witness check:    failed")
                output_file.write("\n    Expected witness   =" + sloth_witn_exp)
                output_file.write("\n    Calculated witness =" + sloth_witn)
            elif ver == self.sloth_unicorn_gen.HASH_FAIL:
                output_file.write("\n  Commitment check: passed")
                output_file.write("\n  Witness check:    passed")
                output_file.write("\n  Hash check:       failed")

            output_file.write("\nRuntime: " + str(runtime))


    def generate_sloth_unicorn(self):

        self.sloth_unicorn_gen.generate()

        with open(self.rawdata_filepath, 'r') as f:
            line = f.readline()
            while line:
                if self._tag_sloth_hash in line:
                    sloth_hash_exp = line.split('=')[1].rstrip()
                elif self._tag_sloth_comm in line:
                    sloth_comm_exp = line.split('=')[1].rstrip()
                elif self._tag_sloth_witn in line:
                    sloth_witn_exp = line.split('=')[1].rstrip()

                line = f.readline()

        sloth_hash = self.sloth_unicorn_gen.get_sloth_hash()
        sloth_comm = self.sloth_unicorn_gen.get_sloth_commitment()
        sloth_witn = self.sloth_unicorn_gen.get_sloth_witness()

        with open(self.output_filepath, 'w') as output_file:

            output_file.write("\nSlothUnicorn checker:\n")

            if sloth_comm == sloth_comm_exp:
                output_file.write("\n  Commitment check: passed")
            else:
                output_file.write("\n  Commitment check: failed")
                output_file.write("\n    Expected commitment   =" + sloth_comm_exp)
                output_file.write("\n    Calculated commitment =" + sloth_comm)

            if sloth_witn == sloth_witn_exp:
                output_file.write("\n  Witness check:    passed")
            else:
                output_file.write("\n  Witness check: failed")
                output_file.write("\n    Expected witness   =" + sloth_witn_exp)
                output_file.write("\n    Calculated witness =" + sloth_witn)

            if sloth_hash == sloth_hash_exp:
                output_file.write("\n  Hash check:       passed")
            else:
                output_file.write("\n  Hash check: failed")
                output_file.write("\n    Expected hash   =" + sloth_hash_exp)
                output_file.write("\n    Calculated hash =" + sloth_hash)

            output_file.write("\n\n")


    def check_curve_gen(self, use_rej):

        start = time.time()

        self.curve_gen.generate(use_rejected=use_rej, \
                                rejected_file=self.rejected_filepath)

        runtime = time.time() - start

        with open(self.rawdata_filepath, 'r') as f:
            line = f.readline()
            while line:
                if self._tag_prime_p in line:
                    prime_p_exp = int(line.split('=')[2].strip().rstrip())
                elif self._tag_coeff_a in line:
                    coeff_a_exp = int(line.split('=')[2].strip().rstrip())
                elif self._tag_coeff_b in line:
                    coeff_b_exp = int(line.split('=')[2].strip().rstrip())
                elif self._tag_point_x in line:
                    point_x_exp = int(line.split('=')[2].strip().rstrip())
                elif self._tag_point_y in line:
                    point_y_exp = int(line.split('=')[2].strip().rstrip())
                elif self._tag_cardinality in line:
                    card_exp = int(line.split('=')[2].strip().rstrip())

                line = f.readline()

        not_primes_failed = self.curve_gen.get_not_primes_failed()

        prime_p = self.curve_gen.get_prime_p()
        coeff_a = self.curve_gen.get_coeff_a()
        coeff_b = self.curve_gen.get_coeff_b()
        point_x = self.curve_gen.get_point_x()
        point_y = self.curve_gen.get_point_y()
        card    = self.curve_gen.get_cardinality()

        with open(self.output_filepath, 'a') as output_file:

            output_file.write("\nCurve generator checker:\n")

            if not_primes_failed:
                curve_index = self.curve_gen.get_curve_index()
                output_file.write("\nVerification failed:")
                output_file.write("\n  Cardinality stated in \
                                       rejected_curves file is not correct")
                output_file.write("\n  Curve index: " + str(curve_index))
                output_file.write("\nRuntime: " + str(runtime))
                return

            if prime_p == prime_p_exp:
                output_file.write("\nPrime p check: passed")
            else:
                output_file.write("\nPrime p check: failed")
                output_file.write("\n    Expected p   =" + str(prime_p_exp))
                output_file.write("\n    Calculated p =" + str(prime_p))
            if coeff_a == coeff_a_exp:
                output_file.write("\nCoeff a check: passed")
            else:
                output_file.write("\nCoeff a check: failed")
                output_file.write("\n    Expected a   =" + str(coeff_a_exp))
                output_file.write("\n    Calculated a =" + str(coeff_a))
            if coeff_b == coeff_b_exp:
                output_file.write("\nCoeff b check: passed")
            else:
                output_file.write("\nCoeff b check: failed")
                output_file.write("\n    Expected b   =" + str(coeff_b_exp))
                output_file.write("\n    Calculated b =" + str(coeff_b))
            if point_x == point_x_exp:
                output_file.write("\nPoint x check: passed")
            else:
                output_file.write("\nPoint x check: failed")
                output_file.write("\n    Expected x   =" + str(point_x_exp))
                output_file.write("\n    Calculated x =" + str(point_x))
            if point_y == point_y_exp:
                output_file.write("\nPoint y check: passed")
            else:
                output_file.write("\nPoint y check: failed")
                output_file.write("\n    Expected y   =" + str(point_y_exp))
                output_file.write("\n    Calculated y =" + str(point_y))
            if card == card_exp:
                output_file.write("\nCardinality check: passed")
            else:
                output_file.write("\nCardinality check: failed")
                output_file.write("\n    Expected n   =" + str(card_exp))
                output_file.write("\n    Calculated n =" + str(card))

            output_file.write("\nRuntime: " + str(runtime))


    def generate_file_paths(self, dir_name, out_file_name):

        dir_path = os.path.join(CURVES_DATA_DIR, dir_name)
        if not os.path.isdir(dir_path):
            print ("Directory does not exist")
            return False

        self.curve_param_dir = dir_path

        all_files = os.listdir(dir_path)
        for f in all_files:
            if TAG_TWEETS_FILE in f:
                self.tweets_filepath = os.path.join(dir_path, f)
            elif TAG_IMAGE_FILE in f:
                self.image_filepath = os.path.join(dir_path, f)
            elif TAG_RAW_DATA_FILE in f:
                self.rawdata_filepath = os.path.join(dir_path, f)
            elif TAG_REJECTED_FILE in f:
                self.rejected_filepath = os.path.join(dir_path, f)

        if not self.tweets_filepath or \
           not self.image_filepath or \
           not self.rawdata_filepath or \
           not self.rejected_filepath:
            print ("Couldn't find all needed files in curve directory")
            return False

        self.output_filepath = os.path.join(dir_path, out_file_name)

        return True

    def set_num_threads(self, n):

        self.curve_gen.set_num_threads(n)


class SlothUnicornGenerator:

    sloth_hash   = None
    commitment   = None
    witness      = None
    witness_hash = None

    verification = None
    COMMIT_FAIL  = -3
    WITNES_FAIL  = -2
    HASH_FAIL    = -1
    ALL_PASSED   =  1

    sloth_prime_len = 2048

    # Number of iterations for flip and ro functions
    sloth_num_iter  = 155000

    tweets_filepath = None
    image_filepath  = None

    def __init__(self, tw_file, img_file):

        self.tweets_filepath = tw_file
        self.image_filepath  = img_file

    def get_sloth_hash(self):
        return self.sloth_hash

    def get_sloth_commitment(self):
        return self.commitment

    def get_sloth_witness(self):
        return self.witness

    # Generates sloth hash from input data
    def generate(self):

        sloth_input = self.generate_sloth_input()

        self.commitment = utils.hash_sha512(sloth_input)

        prime_p = self.generate_prime_p(sloth_input)

        s_int = self.generate_s_int(sloth_input, prime_p)

        flip_mask   = pow(2, self.sloth_prime_len / 2) - 1
        ro_func_exp = (prime_p + 1) / 4

        for i in xrange(self.sloth_num_iter):
            s_int = (s_int ^ flip_mask) % prime_p
            s_int = self.ro_function(s_int, ro_func_exp, prime_p)

        self.witness    = utils.hex_strip(s_int)
        self.sloth_hash = utils.hash_sha512(self.witness)

    # Verifies if given values are correctly generated
    def verify(self, expected_comm, expected_hash, expected_wit):

        sloth_input = self.generate_sloth_input()

        self.commitment = utils.hash_sha512(sloth_input)

        if self.commitment != expected_comm:
            self.verification = self.COMMIT_FAIL
            return False

        wit_hash = utils.hash_sha512(expected_wit)
        if wit_hash != expected_hash:
            self.verification = self.WITNES_FAIL
            self.witness_hash = wit_hash
            return False

        prime_p = self.generate_prime_p(sloth_input)

        s_int = self.generate_s_int(sloth_input, prime_p)

        flip_mask   = pow(2, self.sloth_prime_len / 2) - 1

        inv_val = int(expected_wit, 16)
        for i in xrange(self.sloth_num_iter):
            if inv_val % 2 == 0:
               inv_val = pow(inv_val, 2, prime_p)
            else:
                inv_val = prime_p - pow(inv_val, 2, prime_p)
            inv_val = (inv_val ^ flip_mask) % prime_p

        if inv_val != s_int:
            self.verification = self.HASH_FAIL            
            return False

        self.verification = self.ALL_PASSED
        return True


    def generate_prime_p(self, sloth_input):

        # We divide with 512 because we are using sha512 hash function
        num_hashes = self.sloth_prime_len / 512

        p0_hex = ""
        for i in xrange(num_hashes):
            p0_hex += utils.hash_sha512(sloth_input + "prime" + str(i))

        p0_int = int(p0_hex, 16)
        p1_int = p0_int | pow(2, self.sloth_prime_len - 1)

        prime_p = utils.next_prime_3_mod_4(p1_int)

        return prime_p

    def generate_s_int(self, sloth_input, prime_p):

        num_hashes = self.sloth_prime_len / 512

        s_hex = ""
        for i in xrange(num_hashes):
            s_hex += utils.hash_sha512(sloth_input + "seed" + str(i))

        s_int = int(s_hex, 16)
        s_int = s_int % prime_p

        return s_int

    def ro_function(self, x, exp, p):

        is_qr = utils.is_quadratic_residue(x, p)
        
        if is_qr:
            sq_root = pow(x, exp, p)
            if sq_root % 2 == 0:
                return sq_root
            else:
                return (p - sq_root)
        else:
            sq_root = pow(p - x, exp, p)
            if sq_root % 2 == 0:
                return (p - sq_root)
            else:
                return sq_root

    # Check only if given commitment matches the calculated commitment
    def check_commitment(self, expected_comm):

        sloth_input = self.generate_sloth_input()

        comm = utils.hash_sha512(sloth_input)

        if comm == expected_comm:
            return True
        else:
            return False

    # Read image and tweets files as binary files, concatenate data,
    # hash it with sha512 and return hash digest as a result
    def generate_sloth_input(self):

        img_data = utils.read_binary_file(self.image_filepath)
        tw_data  = utils.read_binary_file(self.tweets_filepath)
        
        img_tw_bytes = bytearray(img_data + tw_data)

        ret_val = utils.hash_sha512(img_tw_bytes)

        return ret_val


class CurveGenerator:

    # Input parameters
    security_level   = None     # 128, 192, 256
    coeff_a_type     = None     # fixed, random, efficient
    montgomery_curve = None     # Montgomery curve or not
    prime_type       = None     # NIST prime, random generated
    input_seed       = None

    # Curve parameters:
    #   y^2 = x^3 + coeff_a * x + coeff_b
    #   coeff_a, coeff_b from GF(prime_p)
    #   point(x, y) on the curve
    prime_p     = None
    coeff_a     = None
    coeff_b     = None
    point_x     = None
    point_y     = None
    cardinality = None

    curve_index = None

    not_primes_failed = None

    # Number of threads to use in generate function
    num_threads = 8
    chunk_size  = 100

    rawdata_filepath = None

    # Tags used to extract input data from raw_data file
    _tag_sec_level  = 'T0_SECURITY'
    _tag_choice_a   = 'T0_A'
    _tag_curve_type = 'T0_MONTGOMERY'
    _tag_prime_type = 'T0_PRIME'
    _tag_sloth_hash = 'T3_SLOTH_HASH'

    def __init__(self, data_file):

        self.rawdata_filepath = data_file
        self.extract_params_from_file()

    def get_prime_p(self):
        return self.prime_p

    def get_coeff_a(self):
        return self.coeff_a

    def get_coeff_b(self):
        return self.coeff_b

    def get_cardinality(self):
        return self.cardinality

    def get_point_x(self):
        return self.point_x

    def get_point_y(self):
        return self.point_y

    def get_curve_index(self):
        return self.curve_index

    def get_not_primes_failed(self):
        return self.not_primes_failed

    def set_num_threads(self, n):
        self.num_threads = n

    # Generates curve from input data
    def generate(self, use_rejected=False, rejected_file=None):

        self.compute_prime_p()

        curve_idx_shared  = multiprocessing.Queue()
        curve_params_res  = multiprocessing.Queue()
        curve_found       = multiprocessing.JoinableQueue()
        lock              = multiprocessing.Lock()

        curve_idx_shared.put(1)
        curve_found.put(0)
        
        if use_rejected and rejected_file:
            rej_ids, rej_vals = self.extract_not_primes(rejected_file)
        else:
            rej_ids  = []
            rej_vals = []

        proc_args = (curve_idx_shared, curve_found, lock, curve_params_res, \
                     use_rejected, rej_ids, rej_vals)

        procs = []
        for i in xrange(self.num_threads):
            procs.append(multiprocessing.Process(target=self.generate_process,
                                                 args=proc_args))

        for p in procs:
            p.start()

        # Wait until any of the processes finds appropriate curve
        curve_found.join()

        # Sleep for 10 seconds to allow the queues
        # to receive all data sent to them
        sleep(10)

        for p in procs:
            if p.is_alive():
                p.terminate()

        idx, a, b, card = curve_params_res.get()

        # If card is -1 this means that we were using rejected_curves file
        # and verification for not_prime curves failed
        self.not_primes_failed = (card == -1)

        self.curve_index = idx
        self.coeff_a = a
        self.coeff_b = b
        self.cardinality = card

        if card != -1:
            self.compute_point_xy()

    def generate_process(self, curve_index, curve_found, lock, curve_result,
                         use_rejected, rejected_ids, rejected_vals):

        chunk_size = self.chunk_size
        prime_p    = self.prime_p
        a_type     = self.coeff_a_type
        in_seed    = self.input_seed
        is_mont    = self.montgomery_curve

        use_rej  = use_rejected
        rej_ids  = rejected_ids
        rej_vals = rejected_vals

        coeff_a = None
        coeff_b = None

        while True:
            lock.acquire()

            curr_idx = curve_index.get()
            curve_index.put(curr_idx + chunk_size)

            lock.release()

            for i in range(chunk_size):

                if coeff_a == None or a_type == 'random':
                    coeff_a = self.compute_coeff_a(a_type, prime_p, \
                                                   in_seed, curr_idx)

                coeff_b = self.compute_coeff_b(prime_p, in_seed, curr_idx)

                # If the curve is secure its cardinality is returned,
                # If not_prime rejected curve verification failed -1
                # is returned, otherwise None is returned
                card = self.check_curve_security(coeff_a, coeff_b, prime_p, \
                                                 is_mont, use_rejected, \
                                                 curr_idx, rej_ids, rej_vals)

                if card:
                    lock.acquire()

                    result = (curr_idx, coeff_a, coeff_b, card)
                    curve_result.put(result)
                    try:
                        curve_found.task_done()
                    except ValueError:
                        # TODO: There is a possibility that more threads
                        #       will call task_done when rajected_curves
                        #       file is used (One thread finds secure curve
                        #       and the other one finds faulty cardinality
                        #       in rejected_curves file).
                        #       This is very very unlikely to happen.
                        print "task_done called too many times"

                    lock.release()
                    return
    
                curr_idx += 1

    def compute_prime_p(self):

        if self.prime_type == 'nist':
            # These are NIST defined primes for different security levels
            if self.security_level == 256:
                self.prime_p = pow(2, 521) - 1
            
            elif self.security_level == 192:
                self.prime_p = pow(2, 384) - pow(2, 128) - \
                               pow(2, 96) + pow(2, 32) - 1
            
            else: # 128 bit secure
                self.prime_p = pow(2, 256) - pow(2, 224) + \
                               pow(2, 192) + pow(2, 96) - 1
        else:
            # If it is not NIST prime then we need to generate random prime
            found = False
            counter = 0
            while not found:
                counter += 1
                in_str = self.input_seed + "p" + str(counter)
                result = utils.hash_sha2k(in_str, self.security_level)
                result_int = int(result, 16)
                
                if self.montgomery_curve == 1:

                    if (result_int % 4 == 3) and is_pseudoprime(result_int):                
                        self.prime_p = result_int
                        found = True
                else:

                    if is_pseudoprime(result_int):                
                        self.prime_p = result_int
                        found = True


    def compute_coeff_a(self, a_type, prime_p, in_seed, curve_index):

        if a_type == 'fixed':
            
            in_str = "a" + in_seed
            result = utils.hash_sha512(in_str)
            result_int = int(result, 16)
            return (result_int % prime_p)
            
        elif a_type == 'random':

            in_str = "a" + str(curve_index) + in_seed
            result = utils.hash_sha512(in_str)
            result_int = int(result, 16)
            return (result_int % prime_p)

        elif a_type == 'efficient':

            return (prime_p - 3)

    def compute_coeff_b(self, prime_p, in_seed, curve_index):
        
        in_str = "b" + str(curve_index) + in_seed
        result = utils.hash_sha512(in_str)
        result_int = int(result, 16)

        return (result_int % prime_p)


    def check_curve_security(self, coeff_a, coeff_b, prime_p, montgomery,
                             use_rejected, curve_id, not_prime_ids, not_prime_vals):

        gf = GF(prime_p)    # Create Sage Galois field
        ab = [coeff_a, coeff_b]
        curve = EllipticCurve(gf, ab)

        # Use rejected_curves file. For curves which passed SEA early abort
        # but are rejected because of cardinality not being prime, we just
        # check if cardinality stated in the file is correct.
        if use_rejected:
            if curve_id in not_prime_ids:
                card = not_prime_vals[not_prime_ids.index(curve_id)]
                rand_point = curve.random_point()
                while rand_point.is_zero():
                    rand_point = curve.random_point()

                rand_point_mul = card * rand_point
                if rand_point_mul.is_zero():
                    if montgomery == 1:
                        rand_point_mul = 4 * rand_point
                        if rand_point_mul.is_zero():
                            return -1
                    return None
                else:
                    return -1 

        if montgomery == 1:
            check_mont = self.is_curve_montgomery(coeff_a, coeff_b, prime_p)
            if not check_mont:
                return None

            curve_magma = magma(curve)
            cardinality = magma.SEA(curve_magma, MaxSmooth=2, AbortLevel=2)
            cardinality = Integer(cardinality)

            if cardinality != 0:

                trace =  prime_p + 1 - cardinality
                cardinality_tw = prime_p + 1 + trace

                card_ok = (cardinality % 4 == 0) and (cardinality_tw % 4 == 0)

                if card_ok:
                    if is_pseudoprime(Integer(cardinality / 4)):
                        if is_pseudoprime(Integer(cardinality_tw / 4)):
                            return cardinality

            return None
        else:
            curve_magma = magma(curve)
            cardinality = magma.SEA(curve_magma, MaxSmooth=1, AbortLevel=2)
            cardinality = Integer(cardinality)

            if cardinality != 0:

                trace =  prime_p + 1 - cardinality
                cardinality_tw = prime_p + 1 + trace

                if is_pseudoprime(cardinality) and \
                   is_pseudoprime(cardinality_tw):
                    return cardinality

            return None

    def is_curve_montgomery(self, coeff_a, coeff_b, prime_p):
        # This check is completly based on the paper:
        # http://saluc.engr.uconn.edu/refs/sidechannel/okeya00elliptic.pdf
        table_mod1 = [[[0, 1], [0, 1]], [[0, 1], [1, 0]]]
        table_mod3 = [[[0, 0], [0, 0]], [[1, 1], [0, 0]]]

        gf = GF(prime_p)
        R = PolynomialRing(gf, 'x')
        R.inject_variables(verbose=False)
        poly  = x**3 + coeff_a * x + coeff_b

        try:
            alpha = poly.any_root()
        except ValueError:
            return False

        tmp = gf(alpha)
        tmp = 3 * (tmp ** 2) + coeff_a

        is_mont = kronecker_symbol(tmp, prime_p) == 1

        if not is_mont:
            return False

        B = tmp ** (-1)
        B = B.square_root()
        A = B * 3
        A = A * alpha

        A1_idx = 0 if kronecker_symbol(A + 2, prime_p) == 1 else 1
        A2_idx = 0 if kronecker_symbol(A - 2, prime_p) == 1 else 1
        B_idx  = 0 if kronecker_symbol(B, prime_p) == 1 else 1

        if prime_p % 4 == 1:
            return table_mod1[A1_idx][A2_idx][B_idx] == 1
        else:
            return table_mod3[A1_idx][A2_idx][B_idx] == 1


    def compute_point_xy(self):

        in_str = self.input_seed + "point"
        x_hash = utils.hash_sha512(in_str)

        self.point_x = int(x_hash, 16) % self.prime_p
        
        end = False
        while not end:
            ring = Integers(self.prime_p)
            tmp  = power_mod(self.point_x, 3, self.prime_p) + \
                   self.coeff_a * self.point_x + self.coeff_b

            y = ring(tmp)
            
            if not utils.is_quadratic_residue(y, self.prime_p):
                x_hash = utils.hash_sha512(x_hash)
                self.point_x = int(x_hash, 16) % self.prime_p

            else:
                sq_root = int(y.square_root())

                if sq_root % 2 == 0:                        
                    self.point_y = sq_root
                else:
                    self.point_y = self.prime_p - sq_root

                end = True


    def extract_params_from_file(self):

        with open(self.rawdata_filepath, 'r') as f:
            line = f.readline()
            while line:
                if self._tag_sec_level in line:
                    self.security_level = int(line.split('=')[1].rstrip())
                elif self._tag_choice_a in line:
                    self.coeff_a_type = line.split('=')[1].strip().rstrip()
                elif self._tag_curve_type in line:
                    self.montgomery_curve = int(line.split('=')[1].rstrip())
                elif self._tag_prime_type in line:
                    self.prime_type = line.split('=')[1].strip().rstrip()
                elif self._tag_sloth_hash in line:
                    self.input_seed = line.split('=')[1].rstrip()

                line = f.readline()

    def extract_not_primes(self, rejected_file):

        rej_ids = []
        rej_vals = []

        with open(rejected_file, 'r') as f:
            line = f.readline()
            while line:
                if ' not_prime' in line:
                    a = line.split('not_prime')[0].strip()
                    b = line.split('not_prime')[1].strip()
                    rej_ids.append(int(a))
                    rej_vals.append(int(b))
                line = f.readline()

        return rej_ids, rej_vals


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='TrxChecker')
    parser.add_argument("dir_name", help="Name of the directory \
                                     with curve parameters", type=str)
    parser.add_argument("-t", "--num_threads", 
                        help="Number of threads to be used in CurveGenerator",
                        type=int)
    parser.add_argument("-ss", "--skip_sloth",
                        help="Skip checking SlothUnicornGenerator",
                        action="store_true")
    parser.add_argument("-sc", "--skip_curve",
                        help="Skip checking CurveGenerator",
                        action="store_true")
    parser.add_argument("-r", "--rejected_curves",
                        help="Use rejected curves file in curve verification",
                        action="store_true")


    args = parser.parse_args()

    trx_checker = TrxChecker(args.dir_name)

    if args.num_threads:
        trx_checker.set_num_threads(args.num_threads)

    trx_checker.check_trx(skip_sloth=args.skip_sloth,
                          skip_curve=args.skip_curve,
                          use_rej=args.rejected_curves)

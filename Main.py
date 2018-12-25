from sage.all import *
from sage.crypto.block_cipher.sdes import SimplifiedDES
from sage.crypto.util import bin_to_ascii
import hashlib as H
import os

# Variables are initialized here for later use. They are described in the below comments
p = 1
q = 1
g = 1
h = 1
x = 1
y = 1
session_key = 1

# This part opens the 'ID.txt' file
directory = os.path.dirname(__file__)
id_file = open(os.path.join(directory, 'ID.txt'))

# This part find the total line length of the 'ID.txt' file for later use
id_file.seek(0, 0)
total_lines = len(id_file.readlines())
id_file.seek(0, 0)


# This definition generates the necessary values for rsa encryption/decryption. Thus the public and the private keys
def rsa_key_generator(power):
    # Random prime numbers are generated up to the power argument
    rsa_p = random_prime(2 ** power, 2 ** (power - 1))
    rsa_q = random_prime(2 ** power, 2 ** (power - 1))

    # n value is calculated
    n = rsa_p * rsa_q
    phi = (rsa_p - 1) * (rsa_q - 1)

    # An appropriate e value is calculated here. 1 < e < phi
    while True:
        rsa_e = randint(2, phi - 1)
        if gcd(rsa_e, n) == 1 and gcd(rsa_e, phi) == 1:
            break

    # Finding the appropriate d value. d * e = 1 mod phi
    bezout_values = xgcd(rsa_e, phi)
    d = Integer(mod(bezout_values[1], phi))

    # Finally public and private keys are generated and returned in a list called keys
    private_key = (n, d)
    public_key = (n, rsa_e)
    keys = (private_key, public_key)
    return keys


# This definition encrypts the given file line by line. It takes public key and a file as parameters
# In this case the public key is actually the session key
def rsa_encryption_file(file, pu_key):
    file.seek(0, 0)
    # pu_key is a list and first element is n and the second element is rsa_e
    n = pu_key[0]
    rsa_e = pu_key[1]

    enc_message = []

    # Reads the file line by line. Makes all letters upper case. Converts each number and letter to ascii numbers.
    # And encrypts them. Each line's result is appended to enc_message list. Which means each element
    # in the list is a line. Finally it returns the enc_message list
    for i in range(total_lines):
        message = file.readline()
        message = message.upper()
        message_in_numbers = ""

        for j in message:
            message_in_numbers += str(ord(j))

        enc_message.append(Integer(message_in_numbers).powermod(rsa_e, n))
    return enc_message


# This definition converts the session key into decimal and encrypts it with the RSA public key of the receiver
def rsa_encryption_session_key(ses_key, pu_key):
    n = pu_key[0]
    rsa_e = pu_key[1]

    # Session key is converted to integer
    ses_key_int = int(str(ses_key), 2)

    # This is the encryption process
    ses_key_locked = Integer(ses_key_int).powermod(rsa_e, n)

    return ses_key_locked


# This definition encrypts the given hashes. It takes public key and a file as parameters
def rsa_encryption_hash(file, pu_key):
    file.seek(0, 0)
    # pu_key is a list and first element is n and the second element is rsa_e
    n = pu_key[0]
    rsa_e = pu_key[1]

    enc_message = []

    # Reads the file line by line. Gets sha1 has of each line. Converts each hash to integer and encrypts them.
    # And each line's result is appended to enc_message list. Which means each element in the list is a line.
    # Finally it returns the enc_message list
    for i in range(total_lines):
        message = file.readline()
        message = H.sha1(message)
        message_in_numbers = str(int(message.hexdigest(), 16))

        enc_message.append(Integer(message_in_numbers).powermod(rsa_e, n))

    return enc_message


# This definition decrypts the encrypted message. It takes private key and the encrypted messages as parameters
def rsa_decryption(enc_message, pr_key):
    # pr_key is a list and first element is n and the second element is d
    d = pr_key[1]
    n = pr_key[0]
    dec_message = []

    # Gets each element of the enc_message list decrypts them. After decryption the results are passed into a list
    # called dec_message. Finally it returns the list dec_message
    for enc_msg in enc_message:
        dec_msg = Integer(enc_msg).powermod(d, n)
        dec_msg = str(dec_msg)
        message_in_chars = ""

        for i in xrange(len(str(dec_msg)) / 2):
            # Takes two numbers from the encrypted message because each two number couple corresponds to a letter
            # or a number.
            asc = dec_msg[i * 2: i * 2 + 2]
            asc = Integer(asc)
            message_in_chars += chr(asc)
        dec_message.append(message_in_chars)

    return dec_message


# This definition takes the lines of the 'ID.txt' file and encrypts it with Simplified DES and the session key
# is used to do that
def simplified_des_encryption_file(file):
    global session_key

    enc_lines = []

    simple_des = SimplifiedDES()
    bin_converter = BinaryStrings()

    # A random key is generated here. Session key. But this is only done once.
    session_key = simple_des.list_to_string(simple_des.random_key())

    # This for loop gets each line and converts them into bits and encrypts them with the session key
    for i in range(total_lines):
        line_in_bits = bin_converter.encoding(file.readline())
        encrypted_line = simple_des(line_in_bits, session_key, algorithm="encrypt")

        # Each result is appended to enc_lines list
        enc_lines.append(encrypted_line)

    # Finally the enc_lines list is returned
    return enc_lines


# This definition takes the RSA encrypted hash value of the 'ID.txt' file and encrypts it with Simplified DES and
# the session key is used to do that
def simplified_des_encryption_hash(hash_list):
    enc_hashes = []

    simple_des = SimplifiedDES()
    bin_converter = BinaryStrings()

    # This for loop gets each element of the hash_list converts them into bits and encrypts them with the session key
    for element in hash_list:
        hash_in_bits = bin_converter.encoding(str(element))
        encrypted_hash = simple_des(hash_in_bits, session_key, algorithm="encrypt")

        # Each result is appended to enc_hashes list
        enc_hashes.append(encrypted_hash)

    # Finally the enc_hashes list is returned
    return enc_hashes


# This definition takes the encrypted lines of the 'ID.txt' file and decrypts them
def simplified_des_decryption(enc_line, ses_key_unlocked):
    # This if condition checks the integer equality of the original session key and the session key that was unlocked
    # by the receiver of the message. If they are not equal this definition will return None. If they are equal
    # we use the original session key because there is no difference between the two.
    if int(str(ses_key_unlocked)) != int(str(session_key), 2):
        print("Session key was not unlocked properly")
        return

    dec_lines = []
    simple_des = SimplifiedDES()

    # This for loop gets the encrypted bits of the 'ID.txt' file and decrypts them with the session key which is
    # checked above
    for i in range(len(enc_line)):
        line_in_bits = enc_line[i]
        decrypted_line = simple_des(line_in_bits, session_key, algorithm="decrypt")
        decrypted_line_in_ascii = ""

        # This for loop converts each 8 bit to their ascii representations, letters and numbers
        for j in range(int(len(decrypted_line) / 8)):
            decrypted_line_in_ascii += str(bin_to_ascii(decrypted_line[j * 8: j * 8 + 8]))

        # Each result is appended in a list
        dec_lines.append(decrypted_line_in_ascii)

    # Finally the dec_lines list is returned
    return dec_lines


# This definition takes an encrypted message and the session key as parameters. Unlike other decryption definition
# this one does not convert integers to letters. It leaves them as integers
def rsa_decryption_to_int(enc_message, pr_key):
    # pr_key is a list and first element is n and the second element is d
    d = pr_key[1]
    n = pr_key[0]
    dec_message = []

    # Gets each element of the enc_message list decrypts them. After decryption the results are passed into a list
    # called dec_message. Finally it returns the list dec_message
    for enc_msg in enc_message:
        dec_msg = Integer(enc_msg).powermod(d, n)
        dec_msg = str(dec_msg)
        dec_message.append(dec_msg)

    return dec_message


# This definition creates message specific digital signatures
def digital_signature_creator():
    M = ""

    # This for loop reads all the lines in the 'ID.txt' file and puts them all in a string
    id_file.seek(0, 0)
    for i in range(total_lines):
        M += id_file.readline()

    # A number k is selected here per-message in order to have different signatures for each message
    # even if the message is the same message. However there is a slight chance for both message and
    # the k value to be the same again in that case the signatures will be the same
    k = randint(1, q)

    print("\nUser's per-message secret number(k): " + str(k))

    # This is the first part of the message specific signature. Which means (g^k mod p) mod q
    r = mod(g.powermod(k, p), q)

    # Inverse of 'k mod q' is created here (k^-1)
    inv_k = inverse_mod(k, q)

    # The message entered by the user is hashed here with SHA-1 hashing algorithm (H(M))
    msg_hash = H.sha1(M)
    # The hashed message is converted into an integer representation
    msg_hash_int = int(msg_hash.hexdigest(), 16)
    # This is the second part of the message specific signature. Which means (k^-1 * (H(M) + x * r)) mod q
    s = Integer(mod(inv_k * (msg_hash_int + x * r), q))

    print("\nSignature: ")
    print("r: " + str(r))
    print("s: " + str(s))

    # Finally the message specific signature has been created here
    signature = (r, s)
    return signature


# This definition is the verification process of the digital signature
def signature_check(signature, received_message):
    print("\nDigital signature verification process has started...")
    print("(This might take more than a few seconds)\n")

    # r and s components of the signature is received here. And the verification process has started
    # received r and s are represented by r' and s'. Also the received message is M'
    rec_r = signature[0]
    rec_s = signature[1]

    message = ""

    # We take the decrypted received message, which is a list, and put all its elements in a string
    for i in received_message:
        message += i

    # The message entered by the user is hashed here with SHA-1 hashing algorithm (H(M))
    msg_hash = H.sha1(message)
    # The hashed message is converted into an integer representation
    msg_hash_int = int(msg_hash.hexdigest(), 16)

    # Verification process continues. First part is calculated here. Which means inverse of "s' mod q" (s^-1)
    w = rec_s.inverse_mod(q)

    # This is the second part of the verification process. Which means (H(M') * w) mod q
    u_1 = mod(msg_hash_int * w, q)
    # This is the second part of the verification process. Which means (r' * w) mod q
    u_2 = mod(rec_r * w, q)

    # An alternative approach to modulus. Which means ((g^u_1 * y^u_2) mod p) mod q
    range_one = Integers(p)
    range_two = Integers(q)
    first_process = range_one(g ** u_1 * y ** u_2)
    second_process = range_two(first_process)

    # v = mod(mod(g^u_1 * y^u_2, p), q). This does the same calculations as the one above
    v = second_process

    # Condition inside print returns True if the signature was correct and could be verified
    print("The result is: " + str(v == rec_r) + " (Signature is successfully verified)")

    if v != rec_r:
        print("\n\n!!! Your signature could not be verified. Please send your message again. !!!")


# This definition calculates values that are necessary for digital signature
def number_calculator():
    global p
    global q
    global g
    global h
    global x
    global y

    # A random prime number is selected with the given ranges
    p = 1
    while p < 2**30:
        #                  | This is the max range
        #                         | This is the min range
        p = random_prime(2**31, 2**30)

    print("\nGlobal public key components:")
    print("p: " + str(p))

    # Number p-1 is factorized to find its prime divisors
    F = factor(p-1)
    # q is set to the greatest prime divisor of p-1
    q = F[len(F)-1][0]

    print("q: " + str(q))

    # Number h is selected to satisfy the condition: 1 < h < p-1
    h = randint(2, p-2)
    # Exponent of h is selected which is determined by p-1 divided by q
    exponent_h = (p-1)/q

    # This is an alternative approach to modulus. Which is actually (h ^ ((p - 1) / q)) mod p
    R = Integers(p)
    g = Integer(R(h**exponent_h))

    print("g: " + str(g))

    # User's private key x is selected to satisfy the condition: 0 < h < q
    x = randint(1, q-1)

    print("\nUser's private key(x): " + str(x))

    # User's public key y is generated: g^x mod p
    y = g.powermod(x, p)

    print("User's public key(y): " + str(y))


# Main menu loop
while True:
    print("\n\n--> Please choose if you want to send messages to test digital signature or read the 'ID.txt' file\n")
    print("1) Read the 'ID.txt' file")
    print("2) Send messages")
    print("3) Exit")

    # The exceptions below check whether you have entered a correct input. If it is wrong you are asked to enter again
    try:
        choice = input("\nYour choice: ")
    except NameError:
        print("\n\n!!! You entered a wrong input !!!\n\n")
        continue

    except SyntaxError:
        print("\n\n!!! You entered a wrong input !!!\n\n")
        continue

    if choice == 1:
        # ------------------------------- Encryption Starts Here -------------------------------

        print("\n\n------ Digital Signature Creation ------")
        # Appropriate values for digital signature are generated here
        number_calculator()

        print("\n\n------ RSA Public/Private Key Creation ------\n")
        # RSA public and private keys of the receiver are generated here with the given power 160
        key_pri, key_pub = rsa_key_generator(160)
        print("Receiver's public key: " + str(key_pub))
        print("Receiver's private key: " + str(key_pri))

        print()

        # RSA public and private keys of the sender are generated here with the given power 160
        key_pri_sender, key_pub_sender = rsa_key_generator(160)
        print("Sender's public key: " + str(key_pub_sender))
        print("Sender's private key: " + str(key_pri_sender))

        print("\n\n------ ID.txt File ------\n")
        id_file.seek(0, 0)
        for i in range(total_lines):
            print(id_file.readline())
        id_file.seek(0, 0)

        print("\n\n------ ID.txt Encrypted With Session Key ------\n")
        # Lines of the 'ID.txt' file are encrypted with Simplified DES and using the session key
        encrypted_lines = simplified_des_encryption_file(id_file)
        print(encrypted_lines)

        print("\n\n------ Session Key ------\n")
        print(str(int(str(session_key), 2)))

        print("\n\n------ RSA Encrypted ID.txt Hash ------\n")
        print("---- With Receiver's Public Key ----\n")
        # Calculated hash value of the 'ID.txt' file is encrypted with RSA public key of the receiver
        rsa_encrypted_hashes = rsa_encryption_hash(id_file, key_pub)
        print(rsa_encrypted_hashes)

        # Calculated hash value of the 'ID.txt' file is encrypted with RSA private key of the sender
        print("\n---- With Sender's Private Key ----\n")
        rsa_encrypted_hashes_sender = rsa_encryption_hash(id_file, key_pri_sender)
        print(rsa_encrypted_hashes_sender)

        print("\n\n------ Session Key Encrypted RSA Encrypted ID.txt Hash ------\n")
        # RSA encrypted hash value is once again encrypted with Simplified DES and using the session key
        encrypted_hashes = simplified_des_encryption_hash(rsa_encrypted_hashes)
        print(encrypted_hashes)

        print("\n\n------ RSA Encrypted Session Key ------\n")
        # Session key is encrypted with RSA public key of the receiver
        session_key_locked = rsa_encryption_session_key(session_key, key_pub)
        print(session_key_locked)

        print("\n\n------ ID.txt Based Digital Signature ------\n")
        # Digital signature is created here with the lines of the 'ID.txt' file and appropriate numbers calculated
        # inside the number_calculator() definition
        digital_signature = digital_signature_creator()

        # ------------------------------- Decryption Starts Here -------------------------------

        print("\n\n------ RSA Decrypted Session Key ------\n")
        # The received encrypted session key is decrypted with the RSA private key of the receiver
        session_key_unlocked = Integer(session_key_locked).powermod(key_pri[1], key_pri[0])
        print(session_key_unlocked)

        print("\n\n------ Session Key Decrypted ID.txt File ------\n")
        # The lines inside 'ID.txt' are decrypted with the decrypted(unlocked) session key
        decrypted_id_information = simplified_des_decryption(encrypted_lines, session_key_unlocked)

        for i in decrypted_id_information:
            print(i)

        print("\n\n------ Session Key Decrypted RSA Encrypted ID.txt Hash ------\n")
        # The encrypted hash value is decrypted with the decrypted(unlocked) session key
        decrypted_hash_values = simplified_des_decryption(encrypted_hashes, session_key_unlocked)
        print(decrypted_hash_values)

        print("\n\n------ RSA Decrypted ID.txt Hash ------\n")
        # The Simplified DES decrypted hash value is decrypted once again with the RSA private key of the receiver
        print("---- With Receiver's Private Key ----\n")
        rsa_decrypted_hash_values = rsa_decryption_to_int(decrypted_hash_values, key_pri)
        print(rsa_decrypted_hash_values)

        # The Simplified DES decrypted hash value is decrypted once again with the RSA public key of the sender
        print("\n---- With Sender's Public Key ----\n")
        rsa_decrypted_hash_values_sender = rsa_decryption_to_int(rsa_encrypted_hashes_sender, key_pub_sender)
        print(rsa_decrypted_hash_values_sender)

        # This part checks whether the original hash values are the same. We decrypt the sender's private key
        # encrypted hash and receiver's public key encrypted hash. If the results are the same we confirm both
        # the integrity of the hash and that it is send by the sender whom we used his/her public key
        print("\n\n------ Sender Validation Result ------\n")
        print("The result is: " + str(rsa_decrypted_hash_values == rsa_decrypted_hash_values_sender) + " (Sender is "
                                                                                                       "successfully"
                                                                                                       " verified)")

        print("\n\n------ Signature Validation Result ------")
        # The digital signature which is sent by the sender is checked here for validation
        signature_check(digital_signature, decrypted_id_information)

    elif choice == 2:
        number_calculator()

        while True:
            try:
                print("\n\nIn order to change your p and q values please type 'NEWPANDQ'\n")
                msg = raw_input("Please enter a message (Type 'EXIT' to end the program): ")

                # Ends the program if the user type 'EXIT'
                if msg == "EXIT":
                    print("\n\nExiting the send messages option...\n\n")
                    break

                # This checks if the user wants new values for p and q. This also changes the values
                # for private and public key
                if msg == "NEWPANDQ":
                    number_calculator()
                    continue

                # A number k is selected here per-message in order to have different signatures for each message
                # even if the message is the same message. However there is a slight chance for both message and
                # the k value to be the same again in that case the signatures will be the same
                k = randint(1, q)

                print("\nUser's per-message secret number(k): " + str(k))

                # This is the first part of the message specific signature. Which means (g^k mod p) mod q
                r = mod(g.powermod(k, p), q)

                # Inverse of 'k mod q' is created here (k^-1)
                inv_k = inverse_mod(k, q)

                # The message entered by the user is hashed here with SHA-1 hashing algorithm (H(M))
                msg_hash = H.sha1(msg)
                # The hashed message is converted into an integer representation
                msg_hash_int = int(msg_hash.hexdigest(), 16)
                # This is the second part of the message specific signature. Which means (k^-1 * (H(M) + x * r)) mod q
                s = Integer(mod(inv_k * (msg_hash_int + x * r), q))

                print("\nSignature: ")
                print("r: " + str(r))
                print("s: " + str(s))

                # Finally the message specific signature has been created here
                signature = (r, s)

                print("\nDigital signature verification process has started...\n")
                print("(Sometimes this process may take more than a few seconds)")
                print("(If you do not want to wait you can use the 'Ctrl + C' combination)")

                # r and s components of the signature is received here. And the verification process has started
                # received r and s are represented by r' and s'. Also the received message is M'
                rec_r = signature[0]
                rec_s = signature[1]

                # The message entered by the user is hashed here with SHA-1 hashing algorithm (H(M))
                msg_hash = H.sha1(msg)
                # The hashed message is converted into an integer representation
                msg_hash_int = int(msg_hash.hexdigest(), 16)

                # Verification process continues. First part is calculated here.
                # Which means inverse of "s' mod q" (s^-1)
                w = rec_s.inverse_mod(q)

                # This is the second part of the verification process. Which means (H(M') * w) mod q
                u_1 = mod(msg_hash_int * w, q)
                # This is the second part of the verification process. Which means (r' * w) mod q
                u_2 = mod(rec_r * w, q)

                # An alternative approach to modulus. Which means ((g^u_1 * y^u_2) mod p) mod q
                range_one = Integers(p)
                range_two = Integers(q)
                first_process = range_one(g ** u_1 * y ** u_2)
                second_process = range_two(first_process)

                # v = mod(mod(g^u_1 * y^u_2, p), q). This does the same calculations as the one above
                v = second_process
                # Condition inside print returns True if the signature was correct and could be verified
                print("The result is: " + str(v == rec_r))

                if v != rec_r:
                    print("\n\n!!! Your signature could not be verified. Please send your message again. !!!")

            except KeyboardInterrupt:
                print("\n\nNew per-message secret key (k) will be set...\n")
                print("You can also type 'NEWPANDQ' command to get new values for p, q, x and y...\n")
                continue

    elif choice == 3:
        # id_file is closed here
        id_file.close()

        print("\n\nExiting the program...\n\n")
        break

    else:
        print("\n\n!!! You entered a wrong input !!!\n\n")

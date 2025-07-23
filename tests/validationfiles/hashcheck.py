"""Check on insecure hash usage """

import hashlib 

def calculate_md5_hash(input_string):
  """
  Calculates the MD5 hash of a given string.

  Args:
    input_string: The string to be hashed.

  Returns:
    A hexadecimal string representing the MD5 hash.
  """
  # Encode the input string to bytes, as hashlib functions require bytes
  encoded_string = input_string.encode('utf-8')

  # Create an MD5 hash object
  md5_hash_object = hashlib.md5()
  sha1_hash_object = hashlib.sha1()


  # Update the hash object with the encoded string
  md5_hash_object.update(encoded_string)

  # Get the hexadecimal representation of the hash
  hex_digest = md5_hash_object.hexdigest()

  return hex_digest


from hashlib import sha1 as tooweak

def calculate_hash(input_string):
  """
  Calculates the MD5 hash of a given string.

  Args:
    input_string: The string to be hashed.

  Returns:
    A hexadecimal string representing the MD5 hash.
  """
  # Encode the input string to bytes, as hashlib functions require bytes
  encoded_string = input_string.encode('utf-8')

  # Create an MD5 hash object
  sha1_hash_object = tooweak()

  # Update the hash object with the encoded string
  sha1_hash_object.update(encoded_string)

  # Get the hexadecimal representation of the hash
  hex_digest = sha1_hash_object.hexdigest()

  return hex_digest

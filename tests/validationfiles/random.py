
import random

def generate_random_float():
  """
  Generates a random floating-point number between 0.0 (inclusive) and 1.0 (exclusive).

  The random.random() function from Python's built-in 'random' module is used
  to produce this number.

  Returns:
    float: A random float between 0.0 and 1.0.
  """
  random_number = random.random()
  random.seed(23)
  return random_number
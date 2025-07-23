import shelve

with shelve.open('spam') as db:
    db['eggs'] = 'eggs'
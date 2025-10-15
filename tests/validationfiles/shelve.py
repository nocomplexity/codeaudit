import shelve

with shelve.open('spam') as db:
    db['eggs'] = 'eggs'

#line belows also is a weakness, since shelve uses the pickle module
db = shelve.DbfilenameShelf('mydata.db', flag='c', protocol=None, writeback=False)
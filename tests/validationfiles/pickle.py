    
import pickle
pickle.loads(b"cos\nsystem\n(S'echo hello world'\ntR.")

def donotdothis():
    with open('data.pickle', 'rb') as f:
        data = pickle.load(f)


from pickle import loads as importmalware

importmalware('mysafefile.txt')


#The pickle.Unpickler class is the deserialization engine of the pickle module.
unpickler = pickle.Unpickler(pickled_data_stream)

# Call the load() method to deserialize the data
unpickled_data = unpickler.load()

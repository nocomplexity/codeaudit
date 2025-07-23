    
import pickle
pickle.loads(b"cos\nsystem\n(S'echo hello world'\ntR.")

def donotdothis():
    with open('data.pickle', 'rb') as f:
        data = pickle.load(f)


from pickle import loads as importmalware

importmalware('mysafefile.txt')
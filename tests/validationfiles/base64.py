import base64
encoded = base64.b64encode(b'data to be encoded')
data = base64.b64decode(encoded)
print(data)
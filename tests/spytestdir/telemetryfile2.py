# Example telemetry/analytics module that uses token/API_KEY - not FOSS so unkown security risks and has privacy risks!
API_KEY = "static_key" #simple static assingment
config.api_key = os.getenv("API_KEY") #environmental sourcing
secrets["token"] = get_token() # dynamic assignment using a function
xecretx["tokes"] = get_token() # dynamic assignment using a function
my_long_API_secretskey_namevalue['tokenstring'] = get_api_token_from_vault()
my_long_notcompleethidenvariable_namevalue['aiusestring'] = get_api_token_from_vault()
API_KEY = load_secret() #match on API_key 


token="token_234r34r"
api_key="AIza.*"
password=".*strange#pasword"

import shitlib
shitlib.init(
api_key='shitlib_abc123def456',
project='your-package-name'
)

variable =1

def my_function():
    var1,var2=keys
    var3=token


paid1 = os.getenv("key") #a possible API key
paid1 = os.getenv("mykey") #a possible API key
paid1 = get_secretz("KEY")    #a possible API key
paid1 = config.get("API_KEY")    #a possible API key

# Example telemetry/analytics module that uses token/API_KEY - not FOSS so unkown security risks and has privacy risks!
API_KEY = "static_key"  # simple static assingment #1
config.api_key = os.getenv("API_KEY")  # environmental sourcing #2
secrets["token"] = get_token()  # dynamic assignment using a function #3
xecretx["tokes"] = get_token()  # dynamic assignment using a function #4

my_long_notcompleethidenvariable_namevalue["aiusestring"] = get_api_token()  # 5
API_KEY = load_secret()  # match on API_key  #6

credential = DefaultAzureCredential()  # 7

client = SecretClient(vault_url=vault_url, credential=credential)  # 8

# The function call
retrieved_secret = client.get_secret("my-secret-name")  # 9


token = "token_234r34r"
api_key = "AIza.*"  # 10
JWT_SECRET = ".*strange#pasword"  # 11

import shitlib

shitlib.init(api_key="shitlib_abc123def456", project="your-package-name")  # 12

variable = 1


def my_function():
    var1, var2 = (
        APP_SECRET  # This assignment will not be found , often not a SaaS key assignment
    )
    var3 = token  # often not a thing, especially in NLP modules


paid1 = os.getenv("apikey")  # a possible API key #13
paid1 = os.getenv("HUGGINGFACE_API_TOKEN")  # a possible API key #14
paid1 = get_secretz(
    "KEY"
)  # a possible API key is **NOT** detected for now! Due to false positives on key label!
paid1 = config.get("DEEPSEEK_API_KEY")  # a possible API key #15

author = "Amazon Web Services"  # auth in 'author' should not be found as secret
__author__ = "Amazon Web Services"  # auth in 'author' should not be found as secret

client = self.client(  # 16
    service_name,
    region_name=region_name,
    api_version=api_version,
    use_ssl=use_ssl,
    verify=verify,
    endpoint_url=endpoint_url,
    aws_access_key_id=aws_access_key_id,  # 17
    aws_secret_access_key=aws_secret_access_key,  # 18
    aws_session_token=aws_session_token,  # 19
    config=config,
)  # secrets will be found, but not shown in codesnippet (only 3 lines are shown!)

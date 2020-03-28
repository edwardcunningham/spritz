from cProfile import run
from os import urandom
from sbox import sbox, unsbox, add_scope, keyring
import gc
# gc.disable()
add_scope(
    scope_name="test", 
    scope_yaml="""{"current_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 
                   "previous_keys":[]}""")

payload = urandom(2**13)
run("""
cpayload = sbox( data=payload, scope='test')
npayload = unsbox(cpayload, scope='test')["data"]
""", sort='cumtime') # ncalls  tottime  percall  cumtime  percall 
assert payload == npayload
print(len(cpayload)/len(payload))
print(gc.get_stats())

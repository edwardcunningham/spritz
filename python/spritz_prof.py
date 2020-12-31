from cProfile import run
from os import urandom
from sbox import sbox, unsbox, add_scope, keyring
import gc
from time import time
from statistics import stdev, mean

gc.disable()
add_scope(
    scope="test", 
    keys="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
)


def kilobytes_per_second(size = 2**10):
    counter = 0
    counters = []
    tic = time()
    while time()-tic < 2.5:
    # while counter < 10:
        loop_tic = time()
        counter += 1
        payload = urandom(size)
        gen_tic = time()
        cpayload = sbox(data=payload, scope='test')
        sbox_tic = time()
        npayload = unsbox(cpayload, scope='test')["data"]
        unsbox_tic = time()
        assert payload == npayload
        counters.append((
            gen_tic - loop_tic,
            sbox_tic - gen_tic,
            unsbox_tic - sbox_tic,
        ))
    toc = time()
    print('size', size/1024, 'Kb')
    for section, index in [('sbox', 1), ('unsbox', 2)]:
        print('    ' + section)
        print('        min    ', min(size/c[index]/1024 for c in counters), 'Kb/s')
        print('        max    ', max(size/c[index]/1024 for c in counters), 'Kb/s')
        print('        mean   ', mean(size/c[index]/1024 for c in counters), 'Kb/s')
        if len(counters)>1:
            print('        stdev  ', stdev(size/c[index]/1024 for c in counters), 'Kb/s')
    print('   ', counter, "iterations", 'in', time()-tic, 'seconds')
# run(
#     """
# kilobytes_per_second(2**10)
# kilobytes_per_second(2**15)
#     """,
#     sort='cumtime'  # ncalls  tottime  percall  cumtime  percall
# )
kilobytes_per_second(2**10)
kilobytes_per_second(2**15)
# kilobytes_per_second(2**20)
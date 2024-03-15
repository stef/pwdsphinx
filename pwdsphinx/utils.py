from itertools import zip_longest # for Python 3.x
def split_by_n(iterable, n):
    return list(zip_longest(*[iter(iterable)]*n, fillvalue=''))

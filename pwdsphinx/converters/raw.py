#!/usr/bin/env python3

def convert(rwd, *opts):
    size = opts[1]
    # rwd[:] does not copy the underlying data, and thus
    # a clearmem() not only wipes the original, but also the copy...
    return rwd[:1] + rwd[1:size]

schema = {"raw": convert}

def main():
    for rwd in sys.stdin:
        print(convert(rwd.strip()))

if __name__ == '__main__':
    main()

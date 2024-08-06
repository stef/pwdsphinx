#!/usr/bin/env python3

def convert(rwd):
    return rwd

schema = {"raw": convert}

def main():
    for rwd in sys.stdin:
        print(convert(rwd.strip()))

if __name__ == '__main__':
    main()

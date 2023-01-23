import sys
import glob

if len(sys.argv) < 3:
    print('Usage: python3 {} <batch dir> <dest dir>'.format(sys.argv[0]))
    sys.exit(1)

# get batch files
files = glob.glob(sys.argv[1]+'/batch*.out')

ctr = 0
#for i in range(len(files)):
for i in range(1):
    fn = '{}/batch{}.out'.format(sys.argv[1], i)
    print('processing', fn)
    fd = open(fn, 'r')
    lines = fd.readlines()

    # split lines into components: (seed, timestamp, request)
    splitlines = []
    for l in lines:
        spl = l.split(',')
        seed = int(spl[0])
        ts = float(spl[1])

        req = ','.join(spl[2:])
        req = req[2:-2]  # remove "b'" and "'\n"
        req = req.replace('\\n', '\n').replace('\\r', '\r')  # replace CRLF

        # now replace hex encoded characters
        while True:
            try:
                idx = req.index('\\x')
                req = req[:idx] + bytes.fromhex(req[idx+2:idx+4]).decode() + req[idx+4:]
            except ValueError:
                break

        splitlines.append((seed, ts, req))
    
    # sort by timestamp
    splitlines.sort(key = lambda x: x[1])

    # write request to file named the current counter value
    for l in splitlines:
        with open('{}/{}'.format(sys.argv[2], ctr), 'w') as fd_out:
            fd_out.write(l[2])
        ctr += 1

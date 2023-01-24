lookup = []

# step 1: map req_id to timestamps
# remember : this isn't a seed. it's the index of the request we sent
with open('body/batch0.out') as fd:
    splitlines = []
    for line in fd:
        spl = line.split(',')
        req_id = int(spl[0])
        ts = float(spl[1]) 
        splitlines.append((req_id, ts))

    splitlines.sort(key = lambda x: x[1])
    for line in splitlines:
        lookup.append(line[1])

# step 2: get coverage for each req_id and print it with timestamp
req_id = 0
with open('body/fuzzer.out') as fd:
    for line in fd:
        if line.startswith('counter:'):
            req_id = int(line[:-1].split(' ')[1])

        if line.startswith('#') and 'cov:' in line:
            spl = line.split()
            for i in range(len(spl)):
                if spl[i] == 'cov:':
                    cov = spl[i+1]
                    break
            print(req_id, lookup[req_id], cov)


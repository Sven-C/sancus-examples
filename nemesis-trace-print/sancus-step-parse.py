#!/usr/bin/python3

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.font_manager as font_manager

def plot_trace(latencies, start, end, out, hsize, vsize, o=''):
    fig = plt.figure(figsize=(hsize,vsize))
    ax = plt.gca()

    font = font_manager.FontProperties(family='monospace', size=12) #weight='bold', style='normal')

    plt.yticks(np.arange(1, 5, 1))

    plt.xlabel('Instruction (interrupt number)')
    plt.ylabel('IRQ latency (cycles)')

    plt.plot(latencies[start:end], '-r' + o)
    plt.savefig(out + '.pdf', bbox_inches='tight')
    plt.show()

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: {} file".format(sys.argv[0]))
        exit()
    fileName = sys.argv[1]
    with open(fileName, "r") as inFile:
        print("Processing {}".format(fileName))
        latencies = [[], []]
        nb = 0
        for line in inFile.readlines():
            line = line[:-1] # strip the newline
            if line.startswith("Trying"):
                nb = int(line.split()[1])
            elif line.startswith("latency"):
                latency = int(line.split()[1])
                latencies[nb].append(latency)
            else:
                print("WARNING: line '{}' is not recognized".format(line))
                pass
        
        minLen = min(len(latencies[0]), len(latencies[1]))
        if len(latencies[0]) != len(latencies[1]):
            print("WARNING: amount of latencies registered differ: {} - {}".format(len(latencies[0]), len(latencies[1])))
        
        for i in range(len(latencies)):
            currentLatencies = latencies[i]
            plot_trace(currentLatencies, 0, minLen+1, 'get-secret-trace-' + str(i), 12, 2)
            plot_trace(currentLatencies, 19, 32, 'get-secret-trace-zoom' + str(i), 12, 2)

if __name__ == "__main__":
    main()


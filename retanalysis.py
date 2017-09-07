#!/usr/bin/python
from __future__ import division
import sys
import argparse

def too_short_intervals(intervals, line_number):
    # heuristic parameters
    short = 3
    super_short = 2
    percent = 90
    sshort_percent = 50
    max_gadget_len = 16

    short_intervals = 0
    super_short_ints = 0
    indx = 0
    for i in intervals:
        if(i < short):
            short_intervals += 1
        if(i < super_short):
            super_short_ints += 1
        # check that the too long gadget is actually inside the gadget chain
        if(i > max_gadget_len and indx not in [1,2,3,14,15,16]):
            return False
        indx += 1

    too_shorts = (short_intervals/len(intervals)) > percent/100
    too_super_shorts = (super_short_ints/len(intervals)) > sshort_percent/100
    if(too_shorts and too_super_shorts):
        print "======================================================="
        print "!!! Too short intervals !!!"
        print "short intervals: " + str((short_intervals/len(intervals))*100)+"%"
        print "super short intervals: " + str((super_short_ints/len(intervals))*100)+"%"
        print "Line number: " + str(line_number)
        print intervals
        print "======================================================="
        return True
    return False

def far_inst_seq(address_dists):
    percent = 40
    far_dist = 0
    for i in address_dists:
        if(i > 0xf000):
            far_dist += 1
    too_far_instructions = (far_dist/len(address_dists)) > percent/100
    if(too_far_instructions):
        print "*******************************************************"
        print "!!! Too large distances !!!"
        print address_dists
        print "large distances: " + str((far_dist/len(address_dists))*100) + "%"
        print "*******************************************************"
        return True
    return False

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("file_name", help="Name of the file, or base name without serial number")
    parser.add_argument("-s", "--single", action="store_true", help="Process single file")
    parser.add_argument("-nodist", action="store_true", help="Omit ret instructions distance heuristic")
    parser.add_argument("-n", type=int, help="Number of files to process")
    args = parser.parse_args()

    file_name = args.file_name
    files_num = 1 if (args.n < 1) else args.n
    single_detection = args.single

    if(files_num == 1):
        trace_file = open(file_name, "r")

    # heuristic parameter
    ret_window_size = 16 #int(sys.argv[3])

    for i in range(files_num):
        if(files_num > 1):
            findex = str(i) if(i>9) else "0" + str(i)
            current_name = file_name[:-4] + findex + file_name[-4:]
            trace_file = open(current_name, "r")

        fifo = []
        address_dists = []
        interval_len = 0
        rop_det = False
        line_number = 0
        prev_addr = 0

        for line in trace_file.readlines():
            if(len(fifo) > ret_window_size):
                fifo.pop(0)
                address_dists.pop(0)

                interval_alert = too_short_intervals(fifo, line_number)

                distance_alert = True if(args.nodist or not interval_alert) else far_inst_seq(address_dists)
                if(single_detection):
                    if(interval_alert and distance_alert):
                        rop_det = True
                        break
                rop_det = rop_det or (interval_alert and distance_alert)

            if("ret" in line or ("jmp" in line and "ptr" in line)):
                curr_addr = int(line.split()[0], 16)
                addr_dist = abs(curr_addr - prev_addr)
                fifo.append(interval_len)
                address_dists.append(addr_dist)
                interval_len = 0
                prev_addr = curr_addr
            else:
                interval_len += 1

            line_number += 1

        print "File "+str(i)+": Rop detected: " + ("Yes" if rop_det else "No")

main()

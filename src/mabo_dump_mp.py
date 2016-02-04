#!/usr/bin/env python2
# Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>

"""
MaBo wrapper that uses multi-processors to dump MRT
"""

import gzip
import bz2
import struct
import subprocess
import sys
import multiprocessing
import os
import argparse


class MRTDispatcher(multiprocessing.Process):
    """ Dispatch an MRT file to multiple file descriptors."""

    def __init__(self, stdin_pipes, fd):
        multiprocessing.Process.__init__(self)
        self.stdin_pipes = stdin_pipes
        self.fd_mrt = fd
        self.numprocess = len(self.stdin_pipes)

    def run(self):
        self.parse_file()
        self.exit()

    def parse_file(self, start_index=0):
        """Parse MRT headers and dispatch dumps to processes"""

        index = start_index
        while True:
            # Get an MRT header
            header = self.fd_mrt.read(8)
            if len(header) == 0:  # no more data to read
                break
            length_str = self.fd_mrt.read(4)
            length = struct.unpack("!I", length_str)[0]
            data = self.fd_mrt.read(length)
            tmp_output = header + length_str + data

            output = "\x00"
            output += struct.pack("!I", len(tmp_output))
            output += struct.pack("!I", index) + tmp_output
            if header[4:] == "\x00\x0d\x00\x01":
                # TABLE_DUMP_v2 must be sent to all processes !
                for i in range(self.numprocess):
                    self.stdin_pipes[i].write(output)
            else:
                # Dispatch MRT dump to processes according to their position
                # in the list
                self.stdin_pipes[index % self.numprocess].write(output)
                index += 1
        return index

    def exit(self):
        """Send the exit code to mabo processes"""
        for i in range(self.numprocess):
            self.stdin_pipes[i].write("\x01\x00\x00\x00\x00\x0f\xff\xff\xff")


class MRTReader(multiprocessing.Process):
    """Read the output of mabo processes and ensure that they are in
       the correct order."""

    def __init__(self, fd_list, json, fd_output=sys.stdout):
        multiprocessing.Process.__init__(self)
        self.fd_list = fd_list
        self.fd_out = fd_output
        self.json = json

    def read_next(self, fd_mrt):
        """ Read the next block from mabo. """
        tmp = ""
        for line in fd_mrt:
            tmp += line
            if line[:-1] == "":
                break
        return tmp

    def run(self):
        next_id = 0
        tmp_dumps = []
        to_remove = []

        while len(self.fd_list):

            for fd_in in self.fd_list:
                dump = self.read_next(fd_in)

                # Check if the process has finished
                if "END" in dump[:3]:
                    to_remove += [fd_in]

                elif "ERROR" in dump[:5]:
                    print >> sys.stderr, dump
                    if "ERROR-FATAL:" in dump[:12]:
                        to_remove = self.fd_list
                        break

                # Output the dumps in the correct order
                else:
                    index = dump.index('\n')
                    dump_id = int(dump[3:index])
                    dump = dump[index+1:]
                    # Remove empty entry
                    if dump == "\n":
                        dump = ""
                    # Remove the last '\n' in json mode
                    if self.json is not True and dump[-1] == "\n":
                        dump = dump[:-1]

                    if len(tmp_dumps) == 0 and dump_id == next_id:
                        # The order is correct (nothing to do)
                        self.fd_out.write(dump)
                        next_id += 1

                    elif len(tmp_dumps) and dump_id == next_id:
                        # The expected ID was received
                        self.fd_out.write(dump)
                        next_id += 1

                        # Sort the stored dumps and display them in
                        # the correct order
                        tmp_l = sorted(tmp_dumps,
                                       cmp=lambda x, y: cmp(x[0], y[0]))
                        for index, data in tmp_l:
                            if index == next_id:
                                self.fd_out.write(data)
                                next_id += 1
                                tmp_dumps.remove((index, data))
                            else:
                                # Out of order
                                break

                    else:
                        # Store out of sequence dumps
                        tmp_dumps += [(dump_id, dump)]

            # Remove fd that are finished
            for fd_in in to_remove:
                self.fd_list.remove(fd_in)
            to_remove = []


def process_mrt(filename, numprocess, mabo_path="./mabo", do_json=False,
                do_shuffle=True):
    """Process MRT dumps using several processes."""

    # Open the MRT file
    if filename[-2:] == "gz":
        try:
            fd_mrt = gzip.open(filename)
            fd_mrt.read(1)  # needed to check if it is a valid gzip file
        except:
            error_message = "%s is not a valid gzip file ! Exiting." % filename
            print >> sys.stderr, error_message
            sys.exit()
        fd_mrt.seek(0)  # go back to the beginning
    elif filename[-3:] == "bz2":
        try:
            fd_mrt = bz2.BZ2File(filename)
            fd_mrt.read(1)  # needed to check if it is a valid bz2
        except:
            error_message = "%s is not a valid bz2 file ! Exiting." % filename
            print >> sys.stderr, error_message
            sys.exit()
        fd_mrt.seek(0)  # go back to the beginning
    else:
        error_message = "Unknown file extension for '%s' ! Exiting." % filename
        print >> sys.stderr, error_message
        sys.exit()

    # FD to and from mabo
    stdin_pipes = []
    stdout_pipes = []

    # Fork some mabo processes
    for _ in range(numprocess):
        try:
            command = [mabo_path, "dump", "--pipe"]
            if do_json:
                command += ["--json"]
            sproc = subprocess.Popen(command, shell=False, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE)
        except:
            print >> sys.stderr, "Can't start %s ! Exiting." % mabo_path
            sys.exit()

        stdin_pipes.append(sproc.stdin)
        stdout_pipes.append(sproc.stdout)

    # Start the MRT dispatcher
    mrt_d = MRTDispatcher(stdin_pipes, fd_mrt)
    mrt_d.start()

    # Start the reader
    if do_shuffle:
        import random
        random.shuffle(stdout_pipes)   # insert some randomness

    mrt_r = MRTReader(stdout_pipes, do_json)
    mrt_r.start()

    mrt_d.join()
    mrt_r.join()


if __name__ == "__main__":

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="multi-processors mabo\
                                                      wrapper")

    parser.add_argument("-b", dest="mabo_path", default="mabo",
                        help="path to the mabo binary")
    parser.add_argument("-j", type=int, dest="numprocess", default=3,
                        help="number of processes to use")
    parser.add_argument("--json", action="store_true", dest="do_json",
                        default=False, help="JSON output")
    parser.add_argument("--shuffle-test", action="store_true",
                        dest="do_shuffle", default=False,
                        help="shuffle data received from mabo, for testing only.")
    parser.add_argument("mrt_dumps", nargs=argparse.REMAINDER,
                        help="List of MRT dumps")
    args = parser.parse_args()

    # Verify arguments
    if args.mrt_dumps == []:
        parser.error("You need to provide a file.")

    # Check if filenames are valid
    for tmp_filename in args.mrt_dumps:
        if not os.path.isfile(tmp_filename):
            parser.error("%s does not exist !" % tmp_filename)

    for tmp_filename in args.mrt_dumps:
        process_mrt(tmp_filename, args.numprocess, mabo_path=args.mabo_path,
                    do_json=args.do_json, do_shuffle=args.do_shuffle)

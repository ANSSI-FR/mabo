# MaBo - MRT and BGP in OCaml


## Overview

Developed since 2011 for the needs of the [French Internet Resilience Observatory](http://www.ssi.gouv.fr/observatoire),
MaBo is a MRT ([RFC6396](https://tools.ietf.org/html/rfc6396)) and BGP
([RFC4271](https://tools.ietf.org/html/rfc4271)) OCaml module, and a standalone
command.

MaBo is able to seamlessly parse raw MRT dumps, as well as compressed (gzip &
bz2) ones. It supports most of the BGP messages and attributes found in [RIPE
RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data)
MRT dumps.


## Authors

  * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
  * Nicolas Vivet <nicolas.vivet@ssi.gouv.fr>


## Building MaBo

MaBo can be easily built on different operating systems. Three different
methods are described below.

### Debian

You need to install the following packages using apt, then build the mabo binary
using make.

```shell
# apt-get install make oasis libbz2-ocaml-dev libzip-ocaml-dev libyojson-ocaml-dev gcc
$ make
```

### OCaml Package Manager (opam)

On other operating systems and distribution, you can install
[opam](https://opam.ocaml.org/doc/Install.html), then type the following command
line. Depending on your installation, you might also need to install the OCaml
compiler, as well as bz2 and gzip headers.

```shell
$ opam pin add mabo . --yes
```

Building MaBo with opam was sucessfully tested on Debian, CentOS, Arch Linux,
FreeBSD 10 and Mac OS X with Homebrew.

### Docker

For convenience, the `Dockerfile` takes care of everything, and build the mabo
binary.  The following command lines show how to build the
[Docker](https://www.docker.com/) image and launch the mabo prefixes sub-command
on a local MRT dump.

```shell
$ docker build -t anssi/mabo .
$ docker run --rm -v $PWD/latest-bview.gz:/bview.gz anssi/mabo prefixes /bview.gz
```

## Usage

MaBo has three sub-commands:

```shell
$ ./mabo 
usage: ./mabo {dump,prefixes,follow} ...

Process MRT dumps

Arguments:
  dump                   Dump the content a MRT file
  prefixes               List AS & prefixes in a MRT file
  follow                 Follow a list of IP prefixes in MRT files
```

### Get some MRT files

To run the following command examples, you will need two MRT dumps available on
the [RIS RIPE](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data) website.
Copying and pasting the following commands in a terminal will grab the
`lastest-bview.gz` and `lastest-update.gz` dumps and store them at your current
location.

```shell
$ wget http://data.ris.ripe.net/rrc01/latest-bview.gz
$ wget http://data.ris.ripe.net/rrc01/latest-update.gz
```

### `mabo dump`

The `dump` sub-command parses a single MRT file, and print the data in MaBo JSON
format. Each line corresponds either to a MRT `TABLE_DUMP_V2` entry, or a BGP
`UPDATE` message. The `--legacy` argument will print the data like
[bgpdump](https://bitbucket.org/ripencc/bgpdump).

```shell
$ ./mabo dump latest-bview.gz | head -n1 | json_pp
{
   "type" : "table_dump_v2",
   "timestamp" : 1431590400,
   "prefix" : "1.0.0.0/24",
   "entries" : [
      {
         "originated_timestamp" : 1431110387,
         "as_path" : "39202 174 15169",
         "peer_as" : 39202,
         "peer_ip" : "195.66.225.2"
      },
      {
         "originated_timestamp" : 1430127204,
         "as_path" : "29636 39326 15169",
         "peer_as" : 29636,
         "peer_ip" : "195.66.224.132"
      },
      {
         "originated_timestamp" : 1431363203,
         "as_path" : "29611 174 15169",
         "peer_as" : 29611,
         "peer_ip" : "2001:7f8:4::73ab:1"
      }
   ]
}
```

When fast processing is needed, the Python script `src/mabo_dump_mp.py` can be
used take advantage of multi-cores. It is a simple wrapper around the dump
sub-command that dispatch the processing to different mabo processes. A bview
MRT dump can then be processed in less than 30 seconds. Here is an example
command using 6 processes.

```shell
$ python ./src/mabo_dump_mp.py -j 6 -b ./mabo latest-bview.gz
```

### `mabo prefixes`

The `prefixes` sub-command parses a single MRT file, and dump a list of AS and
IP prefixes. The `--asn-list` argument can be used to restrict the output to a
specific list of AS numbers.

```shell
$ echo 202214 > asn-list.txt
$ ./mabo prefixes --asn-list asn-list.txt latest-bview.gz | tee | cut -d" " -f2 > prefixes.txt
202214 185.50.64.0/22
202214 185.50.66.0/24
202214 185.50.67.0/24
202214 2a01:a6a0::/32
```

The cut command is here to generate a `prefixes.txt` file as expected by the
`mabo follow` command described bellow.

### `mabo follow`

The `follow` sub-command parses multiple MRT files, whose filenames use the RIS
naming convention. Its first mandatory argument is a file containing IP
prefixes.  It will follow `UPDATE` and `WITHDRAW` messages, and output the
number of monitored prefixes seen at a given timestamp.

```shell
$ ./mabo follow prefixes.txt latest-bview.gz latest-update.gz 
1454227204 1
1454227204 2
1454227204 3
1454227207 4
1454227207 4
```

## Compilation warnings

Depending on your environment, you might encounter the following compilation
warnings, that can be ignored.

### Deprecated modules

Depending on your OCaml compiler, you might get the following error. It is due
to a change in OCaml 4.02 that aims to provide immutable strings.

```
Warning 3: deprecated: String.create
Use Bytes.create instead
```

### C bindings

According to the OCaml documentation, the C bindings warning should be ignored:
```
[..] some C compilers give bogus warnings about unused variables caml__dummy_xxx at
each use of CAMLparam and CAMLlocal. You should ignore them.
```


#### `.deb` package

MaBo can be built as a Debian package using the following commands:

```shell
$ apt-get install debhelper fakeroot ocaml-nox dh-ocaml libyojson-ocaml-dev libeasy-format-ocaml-dev libbiniou-ocaml-dev libzip-ocaml-dev libbz2-ocaml-dev
$ dpkg-buildpackage -us -uc -sa -sa -rfakeroot
```

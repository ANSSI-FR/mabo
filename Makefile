OBUILD=ocamlbuild -j 4 -use-ocamlfind
OBFLAGS=-I src/ -pkgs yojson,biniou,zip,bz2,str

all: mabo

%: src/%.ml src/*.ml
	${OBUILD} ${OBFLAGS} ${@}.native
	mv ${@}.native ${@}

clean:
	$(OBUILD) -clean

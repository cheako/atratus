all: 
	cd lib && make
	cd server && make
	cd tests/static && make
	cd tests/dynamic && make

clean:
	cd lib && make $@
	cd server && make $@
	cd tests/static && make $@
	cd tests/dynamic && make $@

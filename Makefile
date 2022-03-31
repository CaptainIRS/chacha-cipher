_dummy := $(shell mkdir -p build)

default: build/main

build/main: main.cpp chacha.hpp utils.hpp
	g++ -o build/main main.cpp -DLOGS_ENABLED

build/tests: tests.cpp chacha.hpp utils.hpp
	g++ -o build/tests -Icatch2 -DLOGS_ENABLED tests.cpp

build/coverage: tests.cpp chacha.hpp utils.hpp
	g++ -o build/tests -Icatch2 tests.cpp --coverage
	./build/tests
	gcov -o build -rn tests.cpp
	geninfo build/ -b . -o build/coverage.info --exclude "/usr/*"
	genhtml build/coverage.info -o build/coverage

clean:
	rm -rf build

CXX=g++
CXXFLAGS=-std=c++11

.PHONY: all clean

all: lsof

lsof: lsof.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm lsof
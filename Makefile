CXXFLAGS=-g -std=c++11 -Wall -pedantic

all:
	g++ $(CXXFLAGS) -o dns-export main.cpp

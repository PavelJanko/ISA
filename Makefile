CXXFLAGS=-g -std=c++11 -Wall -pedantic -lpcap

all:
	g++ $(CXXFLAGS) -o dns-export main.cpp Query.cpp Query.h Header.cpp Header.h Question.cpp Question.h Record.cpp Record.h

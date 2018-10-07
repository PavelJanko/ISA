CXXFLAGS=-g -std=c++11 -Wall -pedantic

all:
	g++ $(CXXFLAGS) -o ipk-lookup main.cpp Query.cpp Query.h Header.cpp Header.h Question.cpp Question.h Record.cpp Record.h

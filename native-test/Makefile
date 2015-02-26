CXX = g++
CXXFLAGS = -g -Wall -static -fprofile-arcs -ftest-coverage -I./ -I$(CPPUTEST_HOME)/include -I../native/librtmp
LDFLAGS = -L./ -L$(CPPUTEST_HOME)/lib -L../native/librtmp -lCppUTest -lCppUTestExt -lrtmp
CPPUTEST_HOME = /usr
TARGET = rtmptest
SRCS = main.cpp librtmp_test.cpp amf_test.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

test: $(TARGET)
	./$(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CXX) -c $(CXXFLAGS) $^

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $<

.PHONY: clean test
clean:
	rm -f $(TARGET) $(OBJS) *~

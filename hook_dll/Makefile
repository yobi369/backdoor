CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -Wall -shared -std=c++11
LDFLAGS = -static-libgcc -static-libstdc++
OUTPUT_DIR = ../
DLL_NAME = hook_dll.dll
SOURCES = dllmain.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(OUTPUT_DIR)$(DLL_NAME)

$(OUTPUT_DIR)$(DLL_NAME): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(OUTPUT_DIR)$(DLL_NAME)

# Phony targets
.PHONY: all clean

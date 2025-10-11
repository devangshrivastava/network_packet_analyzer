# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
LDFLAGS = -lpthread

# Target executable
TARGET = sniffer

# Source files
SOURCES = main.cpp capture.cpp parser.cpp logger.cpp config.cpp

# Object files (derived from sources)
OBJECTS = $(SOURCES:.cpp=.o)

# Header files (for dependency tracking)
HEADERS = types.hpp capture.hpp parser.hpp logger.hpp config.hpp

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete! Run with: sudo ./$(TARGET)"

# Compile source files to object files
%.o: %.cpp $(HEADERS)
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean complete!"

# Clean and rebuild
rebuild: clean all

# Run the sniffer (requires sudo)
run: $(TARGET)
	@echo "Running sniffer (requires root privileges)..."
	sudo ./$(TARGET)

# Run with example arguments
run-json: $(TARGET)
	@echo "Running sniffer with JSON output..."
	sudo ./$(TARGET) --format json --out logs.json --flush-interval 2 --flush-count 3

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Build the project (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  rebuild   - Clean and rebuild"
	@echo "  run       - Build and run with default settings"
	@echo "  run-json  - Build and run with JSON output"
	@echo "  help      - Show this help message"

# Phony targets (not actual files)
.PHONY: all clean rebuild run run-json help
#pragma once

#include "types.hpp"

// ---------------------------------------------
// Configuration Parsing
// ---------------------------------------------
Config parse_arguments(int argc, char* argv[]);

void print_usage(const char* program_name);
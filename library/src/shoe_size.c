#include "shoe_size.h"
#include <string.h>

double convert_shoe_size(double size, const char* from_system, const char* to_system) {
    // Simple conversion logic (placeholder)
    if (strcmp(from_system, "US") == 0 && strcmp(to_system, "UK") == 0) {
        return size - 1.0;
    } else if (strcmp(from_system, "UK") == 0 && strcmp(to_system, "US") == 0) {
        return size + 1.0;
    } else if (strcmp(from_system, "US") == 0 && strcmp(to_system, "EU") == 0) {
        return size + 33.0;
    } else if (strcmp(from_system, "EU") == 0 && strcmp(to_system, "US") == 0) {
        return size - 33.0;
    } else {
        // Return -1.0 to indicate an unsupported conversion
        return -1.0;
    }
}

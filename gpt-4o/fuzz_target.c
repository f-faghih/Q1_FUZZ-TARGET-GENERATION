#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t
#include <stdlib.h>  // for malloc, free
#include <string.h>  // for memset
#include "KTest.h"   // Include your target header

// Fuzzing entry point 
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < sizeof(KTest)) {
        return 0; // Not enough data to form a valid KTest structure
    }

    // Create a KTest instance and copy data into it
    KTest *ktest = (KTest *)malloc(sizeof(KTest));
    if (!ktest) {
        return 0;
    }
    memset(ktest, 0, sizeof(KTest));

    // Interpret the initial bytes as the number of objects
    ktest->numObjects = data[0] % 5; // Keep it small for testing

    // Allocate memory for objects
    ktest->objects = (KTestObject *)calloc(ktest->numObjects, sizeof(KTestObject));
    if (!ktest->objects) {
        free(ktest);
        return 0;
    }

    // Calculate free data size
    size_t pos = 1; // Start position after `numObjects`
    size_t objectStructSize = sizeof(KTestObject);
    for (unsigned i = 0; i < ktest->numObjects && pos < size; ++i) {
        if (pos + 4 > size) break; // We need at least 4 bytes for numBytes

        // Use next 4 bytes as numBytes for the object
        memcpy(&ktest->objects[i].numBytes, &data[pos], 4);
        pos += 4;

        // Allocate memory for the object bytes
        if (pos + ktest->objects[i].numBytes > size) {
                ktest->objects[i].numBytes = size - pos;
        }
        
        ktest->objects[i].bytes = malloc(ktest->objects[i].numBytes);
        if (ktest->objects[i].bytes) {
            memcpy(ktest->objects[i].bytes, &data[pos], ktest->objects[i].numBytes);
        }
        pos += ktest->objects[i].numBytes;
    }

    // Call the function to fuzz
    (void)kTest_bug(ktest);

    // Free allocated memory
    for (unsigned i = 0; i < ktest->numObjects; i++) {
        free(ktest->objects[i].bytes);
    }
    free(ktest->objects);
    free(ktest);

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>  // Include time.h for the time function
#include "KTest.h"

// Function to parse data into a KTest structure
KTest* parse_kTest(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(KTest)) return NULL; // Ensure there's enough data

    // Create a KTest instance and fill in basic fields
    KTest *kTest = (KTest *)malloc(sizeof(KTest));
    if (!kTest) return NULL;

    kTest->version = KTEST_VERSION;  // Use current version
    kTest->numArgs = 1; // For simplicity, let's just define it as 1
    kTest->args = (char **)malloc(sizeof(char *) * kTest->numArgs);
    kTest->args[0] = NULL; // Keeping args simple

    size_t numObjects = Data[0] % 10 + 1; // Randomly choose number of objects (1-10)
    kTest->numObjects = numObjects;
    kTest->objects = (KTestObject *)malloc(sizeof(KTestObject) * numObjects);
    if (!kTest->objects) {
        free(kTest->args);
        free(kTest);
        return NULL;
    }

    // Fill the KTest structure with data
    // Here, we map the raw data into the KTestObject structure
    const uint8_t *ptr = Data + 1; // Start after the first byte

    for (size_t i = 0; i < numObjects; i++) {
        kTest->objects[i].numBytes = 5 + (ptr[i] % 251); // Assign random size for bytes
        kTest->objects[i].name = (char *)malloc(16); // Fixed length for demonstration
        if (kTest->objects[i].name) {
            for (size_t j = 0; j < 15; j++) {
                kTest->objects[i].name[j] = 'a' + (rand() % 26);
            }
            kTest->objects[i].name[15] = '\0'; // null-terminate

            kTest->objects[i].bytes = (unsigned char *)malloc(kTest->objects[i].numBytes);
            if (kTest->objects[i].bytes) {
                for (size_t j = 0; j < kTest->objects[i].numBytes; j++) {
                    kTest->objects[i].bytes[j] = ptr[i] + j; // Simple filling
                }
            }
        }
        ptr += sizeof(kTest->objects[i].numBytes); // Move to the next byte object info
    }

    return kTest;
}

// Fuzz target function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Parse the input data into the KTest structure
    KTest *kTest = parse_kTest(Data, Size);
    if (!kTest) {
        return 0; // If parsing failed, we simply return
    }

    // Call the function of interest
    unsigned result = kTest_bug(kTest);
    printf("Result of kTest_bug: %u\n", result);

    // Clean up memory
    kTest_free(kTest);

    return 0; // Return 0 to indicate no errors
}
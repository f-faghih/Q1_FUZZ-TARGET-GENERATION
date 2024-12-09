#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // Include for uint8_t
#include <string.h>
#include "KTest.h"

// Define the KTEST_VERSION constant (assuming version 3)
#define KTEST_VERSION 3

// Function to parse data into a KTest structure
KTest* parse_kTest(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint8_t)) return NULL; // Ensure there's at least 1 byte for the number of objects

    // Create a KTest instance and fill in basic fields
    KTest *kTest = (KTest *)malloc(sizeof(KTest));
    if (!kTest) return NULL;

    kTest->version = KTEST_VERSION; // Use current version
    kTest->numArgs = 1; // For simplicity, let's just use 1
    kTest->args = (char **)malloc(sizeof(char *) * kTest->numArgs);
    kTest->args[0] = NULL; // Keeping args simple

    // Randomly choose number of objects (1-10) based on the first byte of Data
    size_t numObjects = (Data[0] % 10) + 1; 
    kTest->numObjects = numObjects;

    // Allocate memory for objects
    kTest->objects = (KTestObject *)malloc(sizeof(KTestObject) * numObjects);
    if (!kTest->objects) {
        free(kTest->args);
        free(kTest);
        return NULL;
    }

    // Fill the KTest structure with data
    const uint8_t *ptr = Data + 1; // Start after the first byte

    for (size_t i = 0; i < numObjects; i++) {
        if (ptr + i >= Data + Size) break;  // Prevent reading beyond input size

        kTest->objects[i].numBytes = 5 + (ptr[i] % 251); // Assign random size for bytes
        kTest->objects[i].name = (char *)malloc(16); // Fixed length for demonstration
        if (kTest->objects[i].name) {
            for (size_t j = 0; j < 15; j++) {
                kTest->objects[i].name[j] = 'a' + (rand() % 26); // Random character a-z
            }
            kTest->objects[i].name[15] = '\0'; // Null terminate
        }

        // Allocate memory for the bytes
        kTest->objects[i].bytes = (unsigned char *)malloc(kTest->objects[i].numBytes);
        if (kTest->objects[i].bytes) {
            for (size_t j = 0; j < kTest->objects[i].numBytes; j++) {
                if (j + i < Size - 1) { // Ensure we don't overflow bounds of the data
                    kTest->objects[i].bytes[j] = ptr[(i + 1 + j) % (Size - 1)]; // Fill with simple values from input
                } else {
                    kTest->objects[i].bytes[j] = 0; // Default fill if out of bounds
                }
            }
        }
    }

    return kTest;
}

// Fuzz target function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Parse the input data into the KTest structure
    KTest *kTest = parse_kTest(Data, Size);
    if (!kTest) {
        return 0; // If parsing failed, we simply return
    }

    // Call the function of interest
    unsigned result = kTest_bug(kTest);
    printf("Result of kTest_bug: %u\n", result);

    // Clean up memory
    kTest_free(kTest); // Use cleanup function to free memory

    return 0; // Return 0 to indicate no errors
}
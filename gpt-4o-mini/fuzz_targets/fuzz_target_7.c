#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // For uint8_t
#include <string.h>
#include <time.h>    // For srand() and time()
#include "KTest.h"   // Ensure this header is correctly included

// Define the KTEST_VERSION constant (assuming version 3)
#define KTEST_VERSION 3

// Function to parse data into a KTest structure
KTest* parse_kTest(const uint8_t *Data, size_t Size) {
    if (Size < 1) return NULL; // Ensure there's at least 1 byte for the number of objects

    // Create a KTest instance and fill in basic fields
    KTest *kTest = (KTest *)malloc(sizeof(KTest));
    if (!kTest) return NULL;

    kTest->version = KTEST_VERSION; // Use the current version
    kTest->numArgs = 1; // For simplicity, we just define it as 1
    kTest->args = (char **)malloc(sizeof(char *) * kTest->numArgs);
    if (!kTest->args) {
        free(kTest);
        return NULL;
    }
    kTest->args[0] = NULL; // Keeping arguments simple

    // Determine the number of objects (1-10) based on the first byte of Data
    size_t numObjects = (Data[0] % 10) + 1; 
    kTest->numObjects = numObjects;

    // The minimum required size for the input must be greater than just the number of objects
    // We must account for the number of bytes required for the object data after headers
    size_t requiredSize = 1 + numObjects; // 1 byte for header + number of bytes for objects

    if (Size < requiredSize) {
        // If there's not enough data, clean up and return
        free(kTest->args);
        free(kTest);
        return NULL; // Not enough data
    }

    // Allocate memory for objects
    kTest->objects = (KTestObject *)malloc(sizeof(KTestObject) * numObjects);
    if (!kTest->objects) {
        free(kTest->args);
        free(kTest);
        free(kTest);
        return NULL; // Allocation failed
    }

    // Fill the KTest structure with data
    const uint8_t *ptr = Data + 1; // Start after the first byte

    for (size_t i = 0; i < numObjects; i++) {
        // Ensure we do not exceed the available data
        if ((i + 1) >= Size) {
            free(kTest->objects);
            free(kTest->args);
            free(kTest);
            return NULL; // Insufficient data to fill object details
        }

        kTest->objects[i].numBytes = 5 + (ptr[i] % 251); // Assign random size for bytes
        kTest->objects[i].name = (char *)malloc(16); // Allocate memory for name
        if (!kTest->objects[i].name) {
            // Free previously allocated memory if name allocation fails
            for (size_t j = 0; j < i; j++) {
                free(kTest->objects[j].name);
                free(kTest->objects[j].bytes);
            }
            free(kTest->objects);
            free(kTest->args);
            free(kTest);
            return NULL; // Allocation failure
        }

        // Fill name with random characters
        for (size_t j = 0; j < 15; j++) {
            kTest->objects[i].name[j] = 'a' + (rand() % 26); // Fill name with random characters
        }
        kTest->objects[i].name[15] = '\0'; // Null terminate

        // Allocate memory for the bytes
        kTest->objects[i].bytes = (unsigned char *)malloc(kTest->objects[i].numBytes);
        if (!kTest->objects[i].bytes) {
            // Free previously allocated memory if bytes allocation fails
            free(kTest->objects[i].name);
            for (size_t j = 0; j < i; j++) {
                free(kTest->objects[j].name);
                free(kTest->objects[j].bytes);
            }
            free(kTest->objects);
            free(kTest->args);
            free(kTest);
            return NULL; // Allocation failure
        }

        // Fill bytes of the object with remaining input data
        for (size_t j = 0; j < kTest->objects[i].numBytes; j++) {
            // Ensure we don't exceed the bounds of the pointer
            kTest->objects[i].bytes[j] = ptr[(i + 1) % (Size - 1)]; // Use modulo to wrap around
        }
    }

    return kTest;
}

// Fuzz target function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Seed the random number generator for varied results on each run
    srand((unsigned int)time(NULL));

    // Parse the input data into the KTest structure
    KTest *kTest = parse_kTest(Data, Size);
    if (!kTest) {
        return 0; // If parsing failed, we simply return
    }

    // Call the function of interest
    unsigned result = kTest_bug(kTest);
   // printf("Result of kTest_bug: %u\n", result);

    // Clean up allocated memory
    kTest_free(kTest); // Use cleanup function to free memory

    return 0; // Return 0 to indicate no errors
}
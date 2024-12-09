#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>  // For uint8_t
#include <string.h>
#include "KTest.h"   // Ensure this header is correctly included

// Define the KTEST_VERSION constant
#define KTEST_VERSION 3

// Function to parse data into a KTest structure
KTest* parse_kTest(const uint8_t *Data, size_t Size) {
    // Ensure there's at least 1 byte for the number of objects
    if (Size < 1) return NULL; 

    // Create a KTest instance
    KTest *kTest = (KTest *)malloc(sizeof(KTest));
    if (!kTest) return NULL;

    kTest->version = KTEST_VERSION; // Use the current version
    kTest->numArgs = 1; // For simplicity, we just define it as 1
    kTest->args = (char **)malloc(sizeof(char *) * kTest->numArgs);
    
    // Ensure args allocation is successful
    if (!kTest->args) {
        free(kTest);
        return NULL;
    }

    kTest->args[0] = NULL; // Keeping arguments simple

    // Determine the number of objects (1-10) based on the first byte of Data
    size_t numObjects = (Data[0] % 10) + 1; 
    kTest->numObjects = numObjects;

    // Validate the input size to avoid overflow
    if (Size < numObjects + 1) { // 1 for the first byte that determines numObjects
        free(kTest->args);
        free(kTest);
        return NULL; // Not enough data
    }

    // Allocate memory for objects
    kTest->objects = (KTestObject *)malloc(sizeof(KTestObject) * numObjects);
    if (!kTest->objects) {
        free(kTest->args);
        free(kTest);
        return NULL; // Allocation failed
    }

    // Fill the KTest structure using the input Data
    for (size_t i = 0; i < numObjects; i++) {
        // Each object size directly determined from input data
        if (i + 1 < Size) { // Ensure we have enough data
            kTest->objects[i].numBytes = Data[i + 1]; // Using input data for numBytes
        } else {
            kTest->objects[i].numBytes = 0; // Fallback
        }

        // Allocate memory for the object name
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

        // Use a deterministic naming convention
        snprintf(kTest->objects[i].name, 16, "object_%zu", i); // Use the index for naming

        // Allocate memory for the bytes of the object
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

        // Fill bytes of the object with data from input
        for (size_t j = 0; j < kTest->objects[i].numBytes; j++) {
            // Ensure we do not exceed the size of input
            if (i + j + 1 < Size) {
                kTest->objects[i].bytes[j] = Data[i + j + 1]; // Fill using input data
            } else {
                kTest->objects[i].bytes[j] = 0; // Default fill if out of bounds
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
//    manual modification by commenting out the printf to make the fuzzing more efficient
//    printf("Result of kTest_bug: %u\n", result);

    // Clean up allocated memory
    kTest_free(kTest); // Use cleanup function to free memory

    return 0; // Return 0 to indicate no errors
}
#include <stdio.h>
#include <stdlib.h>
#include "KTest.h"

// Function to generate random objects for the KTest structure
KTest* generate_random_kTest(size_t numObjects) {
    KTest* kTest = (KTest*) malloc(sizeof(KTest));
    if (!kTest) return NULL;

    kTest->version = kTest_getCurrentVersion();
    kTest->numArgs = 1; // Simple case: 1 argument
    kTest->args = (char**) malloc(sizeof(char*) * kTest->numArgs);
    kTest->args[0] = NULL; // Keeping args simple

    kTest->numObjects = numObjects;
    kTest->objects = (KTestObject*) malloc(sizeof(KTestObject) * numObjects);
    if (!kTest->objects) {
        free(kTest->args);
        free(kTest);
        return NULL;
    }

    for (size_t i = 0; i < numObjects; i++) {
        kTest->objects[i].numBytes = rand() % 256; // Random byte array length (0-255)
        kTest->objects[i].name = malloc(16); // Random name of fixed length
        if (!kTest->objects[i].name) {
            // Clean up previously allocated memory on failure
            for (size_t j = 0; j < i; j++) {
                free(kTest->objects[j].name);
            }
            free(kTest->objects);
            free(kTest->args);
            free(kTest);
            return NULL;
        }

        // Fill name with null-terminated random string
        for (size_t j = 0; j < 15; j++) {
            kTest->objects[i].name[j] = 'a' + (rand() % 26); // a-z
        }
        kTest->objects[i].name[15] = '\0'; // null-terminate

        kTest->objects[i].bytes = (unsigned char*) malloc(kTest->objects[i].numBytes);
        if (kTest->objects[i].bytes) {
            for (size_t j = 0; j < kTest->objects[i].numBytes; j++) {
                kTest->objects[i].bytes[j] = rand() % 256; // Random byte values
            }
        }
    }

    return kTest;
}

int main(int argc, char *argv[]) {
    size_t numObjects = 3; // You can change this to test different scenarios
    KTest* kTest = generate_random_kTest(numObjects);
    if (!kTest) {
        fprintf(stderr, "Failed to allocate memory for KTest structure.\n");
        return 1;
    }

    // Call the kTest_bug function and print the result
    unsigned result = kTest_bug(kTest);
    printf("Result of kTest_bug: %u\n", result);
    
    // Free allocated memory
    kTest_free(kTest);

    return 0;
}
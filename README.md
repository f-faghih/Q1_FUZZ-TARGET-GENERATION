# Fuzz Target Generation with GPT Models

This repository demonstrates the process of generating and refining fuzz targets using two GPT models: **gpt-4o** and **gpt-4o-mini**. The results from each model are stored in separate folders, showcasing differences in prompts, iterations, and outcomes.

## Overview

### **gpt-4o**
- A single prompt was sufficient to generate a functional fuzz target.
- The generated fuzz target successfully identified the bug during fuzzing.

### **gpt-4o-mini**
This model required a more iterative approach, involving **9 prompts**:

1. **Prompt 1**:  
   - The first prompt was used to generate a fuzz target.  
   - Resulted in `fuzz_target_1`, which did not have the correct method signature.  

2. **Prompts 2 to 7**:  
   - `fuzz_target_2` to `fuzz_target_6` also contained errors.  
   - Errors were analyzed, and explanations, along with error messages, were provided to guide GPT model revisions.  

3. **Prompts 8 and 9**:  
   - `fuzz_target_7` and `fuzz_target_8` were functional but inefficient.  
   - The fuzzer took an excessively long time and not finished after several minutes.  
   - Specific hints were provided to optimize the fuzz target.  
   - The final version, `fuzz_target_9`, successfully revealed the bug efficiently.  

#### Manual Modifications  
The only manual modification involved commenting out the `printf` command to ensure fair runtime comparisons between different versions.

---

## Repository Structure

### **gpt-4o/**
- **`kTest.c`** and **`kTest.h`**: Declaration of the target function
- **`prompt.txt`**: The single prompt used to generate a fuzz target.
- **`fuzz_target.c`**: The fuzz target generated by the model.
- **`crash`**: The crash file generated by libFuzzer that triggers the bug.

### **gpt-4o-mini/**
- **`kTest.c`** and **`kTest.h`**: Declaration of the target function
- **`prompts/`**: Contains nine prompts refined iteratively.
- **`fuzz_targets/`**: Contains the nine corresponding fuzz targets generated by the model.
- **`fuzz_target.c`**: The best-performing fuzz target (from the ninth iteration).
- **`crash`**: The crash file generated by libFuzzer that triggers the bug.

---

## Runtime Information

The time taken by libFuzzer to find the bug was measured using the following command on WSL (Windows Subsystem for Linux) on Windows:

`/usr/bin/time -f "%e seconds" ./fuzz_target`

### **gpt-4o**
- The bug was found in 0.83 seconds.

### **gpt-4o-mini**
- The bug was found in 0.29 seconds using the optimized fuzz target (./gpt-4o-mini/fuzz_target.c).

Note: Repeating the fuzzing process may result in different runtimes due to the non-deterministic nature of fuzzing, where each run can explore different paths in the code, leading to variations in the execution time.


---

## Requirements

- Clang 6.0 or higher: A recent version of Clang (starting from version 6.0) is required, as it includes libFuzzer, the fuzzing engine used to generate test cases for the fuzz target.

- libFuzzer: Ensure that libFuzzer is available. It is included with recent Clang versions (from 6.0 onwards). You may need to explicitly install it if using an older or custom version of Clang.

- Linux or WSL (Windows Subsystem for Linux): The provided scripts assume a Linux-based environment, or WSL if you're running on Windows.

---

## How to Use

To compile and run the fuzz target generated by gpt-o or gpt-o-mini, follow these steps:

Navigate to the corresponding folder:

- For gpt-4o, go to the gpt-4o folder.
- For gpt-4o-mini, go to the gpt-4o-mini folder.

Compile the fuzz target: Run the following command to compile the fuzz target using Clang with the necessary sanitizers:

`clang -fsanitize=fuzzer,address -g -o fuzz_target KTest.c fuzz_target.c`

This command compiles fuzz_target.c and KTest.c with the -fsanitize=fuzzer,address flags, which enable fuzzing and address sanitization. The -g flag is used to include debug information.

Run the fuzz target: To start fuzzing and measure the time it takes for libFuzzer to find a bug, run the following command:

`/usr/bin/time -f "%e seconds" ./fuzz_target`

This will execute the compiled fuzz target and display the time taken in seconds.

---

## Contact 
Fathiyeh Faghih
fathieh.faghih@gmail.com
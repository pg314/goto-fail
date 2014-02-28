// -*- c-basic-offset: 8 -*-
#include <stdio.h>
#include <stdlib.h>

#include "tests.h"

static void printUsage(const char *program_name)
{
        const char *usage =
                "Usage:\n"
                "  %s                Run tests\n"
                "  %s iterations     Run benchmark (try 1000000 for iterations)\n";
        fprintf(stderr, usage, program_name, program_name);
}

int main(int argc, char **argv)
{
        if (argc == 1) {
                tests();
        } else if (argc == 2) {
                timeHashDigest(atoi(argv[1]));
        } else {
                printUsage(argv[0]);
                return 1;
        }
        return 0;
}

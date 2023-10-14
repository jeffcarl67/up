#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <getopt.h>

const char usage[] = "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n"
                     "\t-p: set the path to logger.so, default = ./logger.so\n"
                     "\t-o: print output to file, print to \"stderr\" if no file specified\n"
                     "\t--: separate the arguments for logger and for the command\n";

char buf1[8192];

int
main(int argc, char** argv)
{
    char *output = NULL, *sopath = NULL;
    char **child_argv = argv + 1;
    char buf[50] = {0};
    int opt;

    while ((opt = getopt(argc, argv, "o:p:")) != -1) {
        switch(opt) {
        case 'o':
            output = optarg;
            break;
        case 'p':
            sopath = optarg;
            break;
        case '?':
            fprintf(stderr, usage);
            exit(1);
            break;
        }
    }

    if (optind < argc) {
        child_argv = argv + optind;
    }
    else {
        fprintf(stderr, "no command given.\n");
        exit(1);
    }

    if (! output) {
        int fd = dup(2);
        sprintf(buf, "%d", fd);
        setenv("UNIX_HW2_FD", buf, 1);
    }
    else {
        int fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd == -1) {
            perror("open");
            exit(1);
        }
        sprintf(buf, "%d", fd);
        setenv("UNIX_HW2_FD", buf, 1);
    }

    if (!sopath) sopath = "./logger.so";
    realpath(sopath, buf1);
    setenv("LD_PRELOAD", buf1, 1);
    execvp(child_argv[0], child_argv);
    return 0;
}
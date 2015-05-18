#ifndef __LOADER_H__
#define __LOADER_H__

extern void* ld_main(int argc, char **argv, char **env, Elf32_Aux *auxv);
extern void dprintf(const char *str, ...) __attribute__((format(printf,1,2)));

#endif /* __LOADER_H__ */

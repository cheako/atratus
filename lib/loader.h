#ifndef __LOADER_H__
#define __LOADER_H__

extern void* ld_main(int argc, char **argv, char **env, Elf32_Aux *auxv);

#endif /* __LOADER_H__ */

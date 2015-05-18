#ifndef ATRATUS_EMULATE_H__
#define ATRATUS_EMULATE_H__

struct process;

int emulate_instruction(struct process *p, unsigned char *buffer);

#endif /* ATRATUS_EMULATE_H__ */

#ifndef __TTY_H__
#define __TTY_H__

#include "linux-defines.h"

struct _con_filp;

struct con_ops {
	void (*fn_lock)(struct _con_filp *con);
	void (*fn_unlock)(struct _con_filp *con);
	int (*fn_write)(struct _con_filp *con, unsigned char ch);
	void (*fn_get_winsize)(struct _con_filp *con, struct winsize *ws);
};

struct _con_filp {
	filp fp;
	struct con_ops *ops;
	int eof;
	unsigned char ready_data[20];
	int ready_count;
	struct termios tios;
	struct wait_list wl;
};

typedef struct _con_filp con_filp;

void tty_input_add_string(con_filp *con, const char *string);
void tty_input_add_char(con_filp *con, char ch);
void tty_init(con_filp* con);

#endif /* __TTY_H__ */

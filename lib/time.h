#ifndef __ATRATUS_TIME_H__
#define __ATRATUS_TIME_H__

struct tm
{
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

#endif // __ATRATUS_TIME_H__

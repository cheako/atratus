#include <ctype.h>
#include <stdio.h>

#define OK(expr) \
	do { \
		if (!(expr)) \
		{ \
			printf("expression '%s' untrue at %d\n", \
				 #expr, __LINE__); \
			return 0; \
		} \
	} while (0)

int t_isdigit(char ch)
{
	volatile char xc = ch;
	volatile unsigned char xuc = ch;
	return isdigit(xc) && isdigit(xuc);
}

int t_isalpha(char ch)
{
	volatile char xc = ch;
	volatile unsigned char xuc = ch;
	return isalpha(xc) && isalpha(xuc);
}

int t_isalnum(char ch)
{
	volatile char xc = ch;
	volatile unsigned char xuc = ch;
	return isalnum(xc) && isalnum(xuc);
}

int t_toupper(char ch)
{
	volatile char xc = ch;
	return toupper(xc);
}

int t_tolower(char ch)
{
	volatile char xc = ch;
	return tolower(xc);
}

int test_isnum(void)
{
	OK(t_isdigit('0'));
	OK(t_isdigit('9'));
	OK(!t_isdigit(' '));
	OK(!t_isdigit('a'));
	OK(!t_isdigit('A'));
	return 1;
}

int test_toupper(void)
{
	OK(t_toupper('a') == 'A');
	OK(t_toupper('A') == 'A');
	OK(t_toupper('0') == '0');
	OK(t_toupper('z') == 'Z');
	OK(t_toupper(' ') == ' ');
	return 1;
}

int test_isalpha(void)
{
	OK(t_isalpha('A'));
	OK(t_isalpha('Z'));
	OK(t_isalpha('a'));
	OK(t_isalpha('z'));
	OK(!t_isalpha('0'));
	OK(!t_isalpha('!'));
	OK(!t_isalpha(' '));
	OK(!t_isalpha('/'));
	OK(!t_isalpha('\\'));
	OK(!t_isalpha('\n'));
	return 1;
}

int test_isalnum(void)
{
	OK(t_isalnum('A'));
	OK(t_isalnum('Z'));
	OK(t_isalnum('a'));
	OK(t_isalnum('z'));
	OK(t_isalnum('0'));
	OK(t_isalnum('9'));
	OK(!t_isalnum('!'));
	OK(!t_isalnum(' '));
	OK(!t_isalnum('/'));
	OK(!t_isalnum('\\'));
	OK(!t_isalnum('\n'));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_isnum())
		return 1;
	if (!test_toupper())
		return 1;
	if (!test_isalpha())
		return 1;
	if (!test_isalnum())
		return 1;
	printf("OK\n");
	return 0;
}

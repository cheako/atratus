/*
 * exit - just exit, nothing else
 *
 * Copyright (C)  2006-2012 Mike McCormack
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


__asm__ (
	"\n"
".globl _start\n"
"_start:\n"
	"\tmov $1, %eax\n"
	"\tmov $0, %ebx\n"
	"\tmov $0, %ecx\n"
	"\tint $0x80\n"
);

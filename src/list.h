/*
 * linked list implementation
 *
 * Copyright (C)  2013 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#ifndef LIST_H__
#define LIST_H__

/*
 * Double linked list implementation with NULL termination.
 * Elements not in the list should be set to INVALID_ELEMENT.
 */

#define INVALID_ELEMENT ((void*) -1)

#define LIST_ANCHOR(T)							\
	struct { 							\
		T *head;						\
		T *tail;						\
	}

#define LIST_ANCHOR_INIT(anchor)					\
	do {								\
		(anchor)->head = NULL;					\
		(anchor)->tail = NULL;					\
	} while (0)

#define LIST_ELEMENT_INIT(element, NAME)				\
	do {								\
		(element)->next_##NAME = INVALID_ELEMENT;		\
		(element)->prev_##NAME = INVALID_ELEMENT;		\
	} while (0)

#define LIST_ELEMENT(T, NAME)						\
	T *next_##NAME;							\
	T *prev_##NAME;

#define LIST_APPEND(anchor, element, NAME)				\
	do {								\
		if ((anchor)->head == NULL)				\
			(anchor)->head = (element);			\
		else							\
			(anchor)->tail->next_##NAME = (element);	\
		(element)->prev_##NAME = (anchor)->tail;		\
		(element)->next_##NAME = NULL;				\
		(anchor)->tail = (element);				\
	} while (0)

#define LIST_PREPEND(anchor, element, NAME)				\
	do {								\
		if ((anchor)->tail == NULL)				\
			(anchor)->tail = (element);			\
		else							\
			(anchor)->head->prev_##NAME = (element);	\
		(element)->next_##NAME = (anchor)->head;		\
		(element)->prev_##NAME = NULL;				\
		(anchor)->head = (element);				\
	} while (0)

#define LIST_INSERT_AFTER(anchor, member, element, NAME)		\
	do {								\
		assert(!ELEMENT_IN_LIST(element));			\
		if ((member) == NULL)					\
		{							\
			LIST_APPEND(anchor, element, NAME);		\
			break;						\
		}							\
		assert(ELEMENT_IN_LIST(member));			\
		(element)->next_##NAME = (member)->next_##NAME;		\
		(element)->prev_##NAME = (member);			\
		if ((member)->next_##NAME)				\
			(member)->next_##NAME->prev_##NAME = (element);	\
		else							\
			(anchor)->tail = (element);			\
		(member)->next_##NAME = (element);			\
	} while (0)

#define LIST_INSERT_BEFORE(anchor, member, element, NAME)		\
	do {								\
		assert(!ELEMENT_IN_LIST(element, NAME));		\
		if ((member) == NULL)					\
		{							\
			LIST_PREPEND(anchor, element, NAME);		\
			break;						\
		}							\
		assert(ELEMENT_IN_LIST(member, NAME));			\
		(element)->prev_##NAME = (member)->prev_##NAME;		\
		(element)->next_##NAME = (member);			\
		if ((member)->prev_##NAME)				\
			(member)->prev_##NAME->next_##NAME = (element);	\
		else							\
			(anchor)->head = (element);			\
		(member)->prev_##NAME = (element);			\
	} while (0)

#define LIST_EMPTY(anchor)	((anchor)->head == NULL)
#define LIST_HEAD(anchor)	((anchor)->head)
#define LIST_TAIL(anchor)	((anchor)->head)

#define LIST_NEXT(element, NAME) ((element)->next_##NAME)
#define LIST_PREV(element, NAME) ((element)->prev_##NAME)

#define LIST_REMOVE(anchor, element, NAME)				\
	do {								\
		if ((element)->prev_##NAME)				\
			(element)->prev_##NAME->next_##NAME = 		\
						(element)->next_##NAME;	\
		else							\
			(anchor)->head = (element)->next_##NAME;	\
		if ((element)->next_##NAME)				\
			(element)->next_##NAME->prev_##NAME = 		\
						(element)->prev_##NAME;	\
		else							\
			(anchor)->tail = (element)->prev_##NAME;	\
		(element)->next_##NAME = INVALID_ELEMENT;		\
		(element)->prev_##NAME = INVALID_ELEMENT;		\
	} while (0);

#define ELEMENT_IN_LIST(element, NAME)					\
	((void*)((element)->next_##NAME) != INVALID_ELEMENT)

#define LIST_FOR_EACH(anchor, element, NAME) 				\
	for ((element) = LIST_HEAD(anchor);				\
		 (element);						\
		 (element) = LIST_NEXT(element, NAME))

#define	LIST_INSERT_ORDERED(anchor, element, ordering_fn, NAME)		\
	do {								\
		typeof ((anchor)->head) _x, _y;				\
		_x = LIST_HEAD(anchor);					\
		if (!_x)						\
		{							\
			LIST_PREPEND(anchor, element, NAME);		\
			break;						\
		}							\
		while (1)						\
		{							\
			_y = LIST_NEXT(_x, NAME);			\
			if (!ordering_fn(_x, element))			\
			{						\
				LIST_INSERT_BEFORE(anchor, _x,		\
						 element, NAME);	\
				break;					\
			}						\
			if (!_y)					\
			{						\
				LIST_APPEND(anchor, element, NAME);	\
				break;					\
			}						\
			_x = _y;					\
		}							\
	} while (0)

#define LIST_ASSERT_ORDERED(anchor, ordering_fn, NAME)			\
	do {								\
		typeof ((anchor)->head) _x, _y;				\
		LIST_FOR_EACH(anchor, _x, NAME)				\
		{							\
			_y = LIST_NEXT(_x, NAME);			\
			if (!_y)					\
				break;					\
			assert(ordering_fn(_x, _y));			\
		}							\
	} while (0)

#endif // LIST_H__

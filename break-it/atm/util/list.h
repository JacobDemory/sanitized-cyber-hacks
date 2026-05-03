/*
 * This is a simple list that stores key-data pairs.
 * It DOES permit multiple entires with the same key.
 * See list_example.c for an example of how to use it.
 * Feel free to change this as you desire.
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>

typedef struct _ListElem
{
    char *name;
    int pin;
    int balance;
    struct _ListElem *next;
} ListElem;

typedef struct _List
{
    ListElem *head;
    ListElem *tail;
    uint32_t size;
} List;

List* list_create();
void list_free(List *list);
void list_add(List *list, char *name, int pin, int bal);
ListElem* list_find(List *list, const char *name);
void list_del(List *list, const char *name);
uint32_t list_size(const List *list);

#endif



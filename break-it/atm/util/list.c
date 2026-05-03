#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "list.h"
#include <stdio.h>

List* list_create()
{
    List *list = (List*) malloc(sizeof(List));
    list->head = list->tail = NULL;
    list->size = 0;
    return list;
}

void list_free(List *list)
{
    if(list != NULL)
    {
        ListElem *curr = list->head;
        ListElem *next;
        while(curr != NULL)
        {
            // printf("Freeing list elem: %s\n", curr->name);
            next = curr->next;
            free(curr->name);
            free(curr);
            curr = next;
        }
        free(list);
    }
}

ListElem* list_find(List *list, const char *name)
{
    if(list == NULL)
        return NULL;

    ListElem *curr = list->head;
    while(curr != NULL)
    {
        // printf("curr name: %s\n", curr->name); 
        if(strcmp(curr->name, name) == 0)
            return curr;
        curr = curr->next;
    }

    return NULL;
}

void list_add(List *list, char *name, int pin, int balance)
{
    // Allow duplicates
    // assert(list_find(list, name) == NULL);

    ListElem *elem = (ListElem*) malloc(sizeof(ListElem));
    elem->name = strdup(name);
    elem->pin = pin;
    elem->balance = balance;
    elem->next = NULL;

    if(list->tail == NULL) {
        list->head = list->tail = elem;
    }
    else{
        list->tail->next = elem;
        list->tail = elem;
    }
    list->size++;
}

void list_del(List *list, const char *name)
{
    // Remove the element with name 'name'
    ListElem *curr, *prev;

    curr = list->head;
    prev = NULL;
    while(curr != NULL)
    {
        if(strcmp(curr->name, name) == 0)
        {
            // Found it: now delete it

            if(curr == list->tail)
                list->tail = prev;

            if(prev == NULL)
                list->head = list->head->next;
            else
                prev->next = curr->next;

            list->size--;

            free(curr->name);
            free(curr);
            return;
        }

        prev = curr;
        curr = curr->next;
    }
}

uint32_t list_size(const List *list)
{
    return list->size;
}

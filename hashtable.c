/*
 * Name:        Josh Levy
 * Case ID:     jml312
 * Filename:    hashtable.c
 * Created:     10/15/22
 * Description: Hash table implementation with chaining for collisions.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hashtable.h"

#define LOAD_FACTOR 0.75

typedef struct Hashtable
{
  int num_items; // number of current items in hashtable
  int size;      // total number of buckets
  Node **table;  // table of linked lists
} Hashtable;

typedef struct Node
{
  char *key;
  int value;
  Node *next;
} Node;

/* initializes a hash table based on the size given */
Hashtable *ht_create(int size)
{
  Hashtable *hashtable = malloc(sizeof(*hashtable));
  hashtable->table = malloc(size * sizeof(*hashtable->table));
  hashtable->size = size;
  hashtable->num_items = 0;

  for (int i = 0; i < size; i++)
  {
    hashtable->table[i] = NULL;
  }
  return hashtable;
}

/* returns the hash value of a key */
int hash(char *key)
{
  int hash = 0;
  for (int i = 0; i < strlen(key); i++)
  {
    hash += key[i];
  }
  return hash;
}

/* inserts a key-value pair into the hash table with linear chaining.
 * rehashes to the closest prime number to 2 times the current table size
 * if the load is greater than 0.75 */
Node *ht_insert(Hashtable *hashtable, char *key, int value)
{
  Node **temp_node = &hashtable->table[hash(key) % hashtable->size];
  while (*temp_node && strcmp(key, (*temp_node)->key) < 0)
  {
    temp_node = &(*temp_node)->next;
  }

  if (!*temp_node || strcmp(key, (*temp_node)->key) != 0)
  {
    Node *next_node = *temp_node;
    *temp_node = malloc(sizeof(**temp_node));
    (*temp_node)->key = strdup(key);
    (*temp_node)->next = next_node;
    hashtable->num_items++;
  }

  (*temp_node)->value += value;

  if ((double)hashtable->num_items / hashtable->size > LOAD_FACTOR)
  {
    ht_rehash(hashtable, next_prime(hashtable->size * 2));
  }
  return *temp_node;
}

/* rehashes the hash table to the given size */
void ht_rehash(Hashtable *hashtable, int size)
{
  Node **table = malloc(size * sizeof(*table));
  for (int i = 0; i < size; i++)
  {
    table[i] = NULL;
  }

  for (int i = 0; i < hashtable->size; i++)
  {
    Node *current_node = hashtable->table[i];
    while (current_node)
    {
      Node *next_node = current_node->next;
      Node **temp_node = &table[hash(current_node->key) % size];

      while (*temp_node && strcmp(current_node->key, (*temp_node)->key) < 0)
      {
        temp_node = &(*temp_node)->next;
      }

      current_node->next = *temp_node;
      *temp_node = current_node;
      current_node = next_node;
    }
  }
  free(hashtable->table);
  hashtable->table = table;
  hashtable->size = size;
}

/* returns 1 if n is prime else returns 0 */
int is_prime(int n)
{
  if (n <= 1)
    return 0;
  if (n <= 3)
    return 1;
  if (n % 2 == 0 || n % 3 == 0)
    return 0;
  for (int i = 5; i * i <= n; i = i + 6)
    if (n % i == 0 || n % (i + 2) == 0)
      return 0;
  return 1;
}

/* returns the next prime number after n */
int next_prime(int n)
{
  if (n <= 1)
  {
    return 2;
  }
  int prime = n;
  while (!is_prime(++prime))
  {
  }
  return prime;
}

/* prints each key-value pair in the hash table */
void ht_print(Hashtable *hashtable)
{
  for (int i = 0; i < hashtable->size; i++)
  {
    Node *current_node = hashtable->table[i];
    while (current_node)
    {
      printf("%s %i\n", current_node->key, current_node->value);
      current_node = current_node->next;
    }
  }
}
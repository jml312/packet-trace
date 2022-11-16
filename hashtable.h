typedef struct Hashtable Hashtable;
typedef struct Node Node;

Hashtable *ht_create(int size);
int hash(char *key);
Node *ht_insert(Hashtable *hashtable, char *key, int value);
void ht_rehash(Hashtable *hashtable, int size);
int is_prime(int n);
int next_prime(int n);
void ht_print(Hashtable *hashtable);

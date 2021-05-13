#ifndef __FERMAT_H__
#define __FERMAT_H__

#include "crc32/crc32.h"
#include "param.h"
#include "mod.h"
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>

#define Debug 0


struct MyQueue {
    int front, rear, size;
    unsigned int capacity;
    uint32_t *array;
};

struct MyQueue* createNQueue(unsigned int _capacity, int queue_num) {
    struct MyQueue *q = (struct MyQueue*)malloc(queue_num * sizeof(struct MyQueue));
    for (int i = 0; i < queue_num; ++i) {
        q[i].capacity = _capacity;
        q[i].front = q[i].size = 0;
        q[i].rear = _capacity - 1;
        q[i].array = (int*)malloc(_capacity * sizeof(uint32_t));
    }
    return q;
}

bool isFull(struct MyQueue *q) {
    return (q->size == q->capacity);
}

bool isEmpty(struct MyQueue *q) {
    return (q->size == 0);
}

void enqueue(struct MyQueue *q, uint32_t item) {
    if (isFull(q)) { printf("enqueue full queue\n"); return; }
    q->rear = (q->rear + 1) % q->capacity;
    q->array[q->rear] = item;
    ++q->size;
}

int dequeue(struct MyQueue *q) {
    if (isEmpty(q)) { printf("dequeue empty queue\n"); return -1; }
    int item = q->array[q->front];
    q->front = (q->front + 1) % q->capacity;
    --q->size;
    return item;
}

void clearnqueue(struct MyQueue *q, int num) {
    for (int i = 0; i < num; ++i) 
        free(q[i].array);
    free(q);
}

uint32_t real_hash(uint32_t poly, uint8_t *data, size_t cnt, int width) {
    return (crc32_hash(poly, data, cnt) & ((1 << width) - 1));
}

void combine(uint32_t srcip, uint32_t dstip, uint32_t sdport, uint32_t rest, uint8_t* result)
{
    uint32_t srcip1=htonl(srcip);
    uint32_t dstip1=htonl(dstip);
    uint8_t *sipptr=(uint8_t *)&srcip1;
    uint8_t *dipptr=(uint8_t *)&dstip1;

    uint32_t sdport1 = htonl(sdport); 
    uint8_t *llptr = (uint8_t *)&sdport1;

    uint16_t rest1 = htons((uint16_t)rest);
    uint8_t *restptr = (uint8_t *)&rest1;

    memcpy(result, sipptr, 4);
    memcpy(result+4, dipptr, 4);
    memcpy(result+8, llptr, 4);
    memcpy(result+12, restptr ,2);
}


struct fermat (*sub(struct fermat a[][entry_num], struct fermat b[][entry_num]))[entry_num] {
    struct fermat (*f)[entry_num] = (struct fermat (*)[entry_num])malloc(sizeof(struct fermat) * array_num * entry_num);
    for (int i = 0; i < array_num; ++i) {
        for (int j = 0; j < entry_num; ++j) {
            f[i][j].ipsrc = ((uint64_t)a[i][j].ipsrc + PRIME - b[i][j].ipsrc) % PRIME;
            f[i][j].ipdst = ((uint64_t)a[i][j].ipdst + PRIME - b[i][j].ipdst) % PRIME;
            f[i][j].sdport = ((uint64_t)a[i][j].sdport + PRIME - b[i][j].sdport) % PRIME;
            f[i][j].rest = ((uint64_t)a[i][j].rest + PRIME - b[i][j].rest) % PRIME;
            f[i][j].counter = a[i][j].counter - b[i][j].counter; // counter is unsighed int
        }
    }

    return f;
}

void insert(struct fermat f[][entry_num], uint32_t ipsrc, uint32_t ipdst, uint16_t sport, uint16_t dport, uint8_t proto, uint8_t err, uint32_t *poly, uint32_t fp_poly) {
    uint32_t sdport = 0, rest = 0;
    rest |= ((ipsrc >> 16) & 0xc000);
    ipsrc &= 0x3fffffff;
    rest |= ((ipdst >> 18) & 0x3000);
    ipdst &= 0x3fffffff;
    sdport = ((uint32_t)sport << 16) | (uint32_t)dport;
    rest |= ((sdport >> 20) & 0xc00);
    sdport &= 0x3fffffff;
    rest |= ((uint32_t)proto << 2);
    rest |= ((uint32_t)err & 0x3);

    uint8_t *data = (uint8_t *)malloc(14);
    combine(ipsrc, ipdst, sdport, rest, data);
    uint32_t fingprint = real_hash(fp_poly, data, 14, 14);
    rest |= (fingprint << 16);

    for (int i = 0; i < array_num; ++i) {
        uint32_t hash_v = real_hash(poly[i], data, 14, 9);
        f[i][hash_v].ipsrc = ((uint64_t)f[i][hash_v].ipsrc + (uint64_t)ipsrc) % PRIME;
        f[i][hash_v].ipdst = ((uint64_t)f[i][hash_v].ipdst + (uint64_t)ipdst) % PRIME;
        f[i][hash_v].sdport = ((uint64_t)f[i][hash_v].sdport + (uint64_t)sdport) % PRIME;
        f[i][hash_v].rest = ((uint64_t)f[i][hash_v].rest + (uint64_t)rest) % PRIME;
        f[i][hash_v].counter = f[i][hash_v].counter + 1;
    }

    free(data);
}

void insert_with_pos(struct fermat f[][entry_num], uint32_t ipsrc, uint32_t ipdst, uint32_t sdport, uint32_t rest, int *pos) {
    for (int i = 0; i < array_num; ++i) {
        f[i][pos[i]].ipsrc = ((uint64_t)f[i][pos[i]].ipsrc + (uint64_t)ipsrc) % PRIME;
        f[i][pos[i]].ipdst = ((uint64_t)f[i][pos[i]].ipdst + (uint64_t)ipdst) % PRIME;
        f[i][pos[i]].sdport = ((uint64_t)f[i][pos[i]].sdport + (uint64_t)sdport) % PRIME;
        f[i][pos[i]].rest = ((uint64_t)f[i][pos[i]].rest + (uint64_t)rest) % PRIME;
        f[i][pos[i]].counter = f[i][pos[i]].counter + 1;
    }
} 

void push_to_fermat(struct fermat f[][entry_num], uint32_t ipsrc, uint32_t ipdst, uint32_t sdport, uint32_t rest, uint32_t counter, int *pos) {
    for (int i = 0; i < array_num; ++i) {
        f[i][pos[i]].ipsrc = ((uint64_t)f[i][pos[i]].ipsrc + (uint64_t)ipsrc) % PRIME;
        f[i][pos[i]].ipdst = ((uint64_t)f[i][pos[i]].ipdst + (uint64_t)ipdst) % PRIME;
        f[i][pos[i]].sdport = ((uint64_t)f[i][pos[i]].sdport + (uint64_t)sdport) % PRIME;
        f[i][pos[i]].rest = ((uint64_t)f[i][pos[i]].rest + (uint64_t)rest) % PRIME;
        f[i][pos[i]].counter = ((uint64_t)f[i][pos[i]].counter + (uint64_t)counter) % PRIME;
    }
}

bool verify(struct fermat f[][entry_num], uint32_t fp_poly, uint32_t* poly, int row, int col, struct MyQueue *q, bool first_round) {
    uint64_t counter_res;
    uint32_t ipsrc, ipdst, sdport, rest, fingprint;
    if (f[row][col].counter & 0x80000000) { // negative
        counter_res = powMod32(~f[row][col].counter + 1, PRIME - 2, PRIME);
        ipsrc = mulMod32(PRIME - f[row][col].ipsrc, counter_res, PRIME);
        ipdst = mulMod32(PRIME - f[row][col].ipdst, counter_res, PRIME);
        sdport = mulMod32(PRIME - f[row][col].sdport, counter_res, PRIME);
        rest = mulMod32(PRIME - f[row][col].rest, counter_res, PRIME);
    }
    else { // positive
        counter_res = powMod32(f[row][col].counter, PRIME - 2, PRIME);
        ipsrc = mulMod32(f[row][col].ipsrc, counter_res, PRIME);
        ipdst = mulMod32(f[row][col].ipdst, counter_res, PRIME);
        sdport = mulMod32(f[row][col].sdport, counter_res, PRIME);
        rest = mulMod32(f[row][col].rest, counter_res, PRIME);
    }
    fingprint = (rest >> 16) & 0x3fff;

    // finger print verification
    uint8_t *data = (uint8_t *)malloc(14);
    combine(ipsrc, ipdst, sdport, rest, data);
    uint32_t hash_v = real_hash(fp_poly, data, 14, 14);
    //printf("%x, %x, %x, %x, %x, %x, %d\n", ipsrc, ipdst, sdport, rest, fingprint, hash_v, f[row]->counter[col]);
    if (hash_v != fingprint) {
        // printf("impure\n");
        free(data);
        return false;
    }
    
    hash_v = real_hash(poly[row], data, 14, 9);
    if (hash_v != col) {
        free(data);
        return false;
    } 
    
    for (int k = 0; k < array_num; ++k) {
        if (k == row) continue;
        hash_v = real_hash(poly[k], data, 14, 9);
        f[k][hash_v].ipsrc = ((uint64_t)f[k][hash_v].ipsrc + PRIME - f[row][col].ipsrc) % PRIME;
        f[k][hash_v].ipdst = ((uint64_t)f[k][hash_v].ipdst + PRIME - f[row][col].ipdst) % PRIME;
        f[k][hash_v].sdport = ((uint64_t)f[k][hash_v].sdport + PRIME - f[row][col].sdport) % PRIME;
        f[k][hash_v].rest = ((uint64_t)f[k][hash_v].rest + PRIME - f[row][col].rest) % PRIME;
        f[k][hash_v].counter = f[k][hash_v].counter - f[row][col].counter;
        if (first_round) {
            if (k < row)
                enqueue(q + k, hash_v);
        }
        else 
            enqueue(q + k, hash_v);
    }

    free(data);

    // decode 5-tuple
    f[row][col].ipsrc = ipsrc;
    f[row][col].ipdst = ipdst;
    f[row][col].sdport = sdport;
    f[row][col].rest = rest;
    
    return true;
}

void extract(struct fermat *fm, int col, struct Flow *f) {
    // restore the original 5-tuple
    uint32_t sip = (fm[col].rest & 0xc000) >> 14;
    uint32_t dip = (fm[col].rest & 0x3000) >> 12;
    uint32_t ll = (fm[col].rest & 0xc00) >> 10;
    uint8_t proto = (fm[col].rest & 0x3fc) >> 2;
    uint8_t err = (fm[col].rest & 0x3);
    ll = (ll << 30) | fm[col].sdport;

    f->ipsrc = (sip << 30) | fm[col].ipsrc;
    f->ipdst = (dip << 30) | fm[col].ipdst;
    f->src_port = (uint16_t)(ll >> 16);
    f->dst_port = (uint16_t)ll;
    f->protocol = proto;
    f->counter = fm[col].counter;
    f->errorcode = err;
}

// counter?
struct lossResult* decode(struct fermat a[][entry_num], struct fermat b[][entry_num], uint32_t *poly, uint32_t fp_poly) {
    struct fermat (*sub_f)[entry_num] = sub(a, b);
    struct MyQueue *candidate = createNQueue(entry_num * array_num, array_num);
    uint8_t data[14];
    int unprocessed = array_num * entry_num;
    bool processed[array_num][entry_num] = { 0 };

    for (int i = 0; i < array_num; ++i)
        for (int j = 0; j < entry_num; ++j) {
            if (sub_f[i][j].counter == 0) {
                processed[i][j] = true;
                --unprocessed;
            }
            else if (verify(sub_f, fp_poly, poly, i, j, candidate, true)) {
                --unprocessed;
                processed[i][j] = true;
            } 
        }
    
    bool pause = false;
    while (unprocessed) {
        pause = true;
        for (int i = 0; i < array_num; ++i) {
            if (!isEmpty(candidate + i)) pause = false;
            while (!isEmpty(candidate + i)) {
                int check_id = dequeue(candidate + i);
                if (processed[i][check_id]) continue;
                if (sub_f[i][check_id].counter == 0) {
                    processed[i][check_id] = true;
                    --unprocessed;
                }
                else if (verify(sub_f, fp_poly, poly, i, check_id, candidate, false)) {
                    processed[i][check_id] = true;
                    --unprocessed;
                }
            }
        }
        if (pause) break;
    }

    #if Debug
    int falsecnt = 0;
    for (int i = 0; i < array_num; ++i)
        for (int j = 0; j < entry_num; ++j)
            if (!processed[i][j]) {
                falsecnt++;
            }
    printf("%d\n", falsecnt);
    #endif

    clearnqueue(candidate, array_num);

    if (unprocessed) {
        printf("decode error\n");
        free(sub_f);
        return NULL;
    }

    struct lossResult *res = (struct lossResult *)malloc(sizeof(struct lossResult));
    res->loss_num = 0;

    for (int i = 0; i < array_num; ++i) {
        for (int j = 0; j < entry_num; ++j) {
            if (sub_f[i][j].counter) {
                extract(sub_f[i], j, &res->f[res->loss_num]);
                ++res->loss_num;
            }
        }
    }

    free(sub_f);
    return res;
}

void display(struct fermat f[][entry_num]) {
    for (int i = 0; i < array_num; ++i) {
        printf("--- %d-th array ---\n", i);
        for (int j = 0; j < entry_num; ++j)
            if (f[i][j].counter) {
                printf("%d-pos: %d %d %d %d %d\n", j, f[i][j].ipsrc, f[i][j].ipdst, f[i][j].sdport, f[i][j].rest, f[i][j].counter);
            }
    }
    printf("\n");
}

#endif
#ifndef _FERMAT_H_
#define _FERMAT_H_

#include <iostream>
#include <cstdint>
#include <unordered_map>
#include <queue>
#include <cstring>
#include "util/BOBHash32.h"
#include "util/mod.h"
#include "util/prime.h"

using namespace std;

#define DEBUG_F 0

// fingprint no used

// use a 16-bit prime, so 2 * a mod PRIME will not overflow
static const uint32_t PRIME_ID = MAXPRIME[16];
static const uint32_t PRIME_FING = MAXPRIME[16];

class Fermat {  
    // arrays
    int array_num;
    int entry_num;
    uint32_t **id;
    uint32_t **fingerprint;
    uint32_t **counter;
    // hash
    BOBHash32 *hash;
    BOBHash32 *hash_fp;

    uint32_t *table;

    bool use_fing;

public:
    int pure_cnt;

    void create_look_up_table() {
        table = new uint32_t[PRIME_ID];
        for (uint32_t i = 0; i < PRIME_ID; ++i)
            table[i] = powMod32(i, PRIME_ID - 2, PRIME_ID);
    }

    void clear_look_up_table() {
        delete [] table;
    }

    void create_array() {
        pure_cnt = 0;
        // id
        id = new uint32_t*[array_num];
        for (int i = 0; i < array_num; ++i) {
            id[i] = new uint32_t[entry_num];
            memset(id[i], 0, entry_num * sizeof(uint32_t));
        }
        // fingerprint
        if (use_fing) {
            fingerprint = new uint32_t*[array_num];
            for (int i = 0; i < array_num; ++i) {
                fingerprint[i] = new uint32_t[entry_num];
                memset(fingerprint[i], 0, entry_num * sizeof(uint32_t));
            }    
        }
        
        // counter
        counter = new uint32_t*[array_num];
        for (int i = 0; i < array_num; ++i) {
            counter[i] = new uint32_t[entry_num];
            memset(counter[i], 0, entry_num * sizeof(uint32_t));
        }
    }

    void clear_array() {
        for (int i = 0; i < array_num; ++i)
            delete [] id[i];
        delete [] id;

        if (fingerprint) {
            for (int i = 0; i < array_num; ++i)
                delete [] fingerprint[i];
            delete [] fingerprint;    
        }
        
        for (int i = 0; i < array_num; ++i)
            delete [] counter[i];
        delete [] counter;
    }

    Fermat(int _a, int _e, bool _fing, uint32_t _init) : array_num(_a), entry_num(_e), use_fing(_fing), fingerprint(nullptr), hash_fp(nullptr) {
        create_array();
        // hash
        if (use_fing)
            hash_fp = new BOBHash32(_init);
        hash = new BOBHash32[array_num];
        for (int i = 0; i < array_num; ++i) 
            hash[i].initialize(_init + i + 1);
    }

    Fermat(int _memory, bool _fing, uint32_t _init) : use_fing(_fing), fingerprint(nullptr), hash_fp(nullptr) {
        array_num = 3;
        if (use_fing)
            entry_num = _memory / (array_num * 12);
        else
            entry_num = _memory / (array_num * 8);
            
        // cout << "construct fermat with " << entry_num << " entry" << endl;
        create_array();
        create_look_up_table();
        // hash
        if (use_fing)
            hash_fp = new BOBHash32(_init);
        hash = new BOBHash32[array_num];
        for (int i = 0; i < array_num; ++i) 
            hash[i].initialize(_init + i + 1);
    }

    ~Fermat() {
        clear_array();
        clear_look_up_table();
        if (hash_fp)
            delete hash_fp;
        delete [] hash;
    }

    void Insert(uint32_t flow_id, uint32_t cnt) {
        if (use_fing) {
            uint32_t fing = hash_fp->run((char*)&flow_id, sizeof(uint32_t));
            for (int i = 0; i < array_num; ++i) {
                uint32_t pos = hash[i].run((char*)&flow_id, sizeof(uint32_t)) % entry_num;
                id[i][pos] = (id[i][pos] + mulMod(flow_id, cnt, PRIME_ID)) % PRIME_ID;
                fingerprint[i][pos] = ((uint64_t)fingerprint[i][pos] + mulMod32(fing, cnt, PRIME_FING)) % PRIME_FING;
                counter[i][pos] += cnt;
            }    
        }
        else {
            for (int i = 0; i < array_num; ++i) {
                uint32_t pos = hash[i].run((char*)&flow_id, sizeof(uint32_t)) % entry_num;
                id[i][pos] = (id[i][pos] + (flow_id * cnt) % PRIME_ID) % PRIME_ID;
                counter[i][pos] += cnt;
            } 
        }
        
    }
    
    void Insert_one(uint32_t flow_id) {
        // flow_id should < PRIME_ID
        if (use_fing) {
            uint32_t fing = hash_fp->run((char*)&flow_id, sizeof(uint32_t)) % PRIME_FING;
            for (int i = 0; i < array_num; ++i) {
                uint32_t pos = hash[i].run((char*)&flow_id, sizeof(uint32_t)) % entry_num;
                id[i][pos] = (id[i][pos] + (flow_id % PRIME_ID)) % PRIME_ID;
                fingerprint[i][pos] = ((uint32_t)fingerprint[i][pos] + (uint32_t)fing) % PRIME_FING;
                counter[i][pos]++;
            }
        }
        else {
            for (int i = 0; i < array_num; ++i) {
                uint32_t pos = hash[i].run((char*)&flow_id, sizeof(uint32_t)) % entry_num;
                id[i][pos] = (id[i][pos] + flow_id) % PRIME_ID;
                counter[i][pos]++;
            }
        }
    }

    void Delete_in_one_bucket(int row, int col, int pure_row, int pure_col) {
        // delete (flow_id, fing, cnt) in bucket (row, col)
        id[row][col] = (PRIME_ID + id[row][col] - id[pure_row][pure_col]) % PRIME_ID;
        if (use_fing)
            fingerprint[row][col] = ((uint32_t)PRIME_FING + (uint32_t)fingerprint[row][col] - fingerprint[pure_row][pure_col]) % PRIME_FING;
        counter[row][col] -= counter[pure_row][pure_col];
    }

    bool verify(int row, int col, uint32_t &flow_id, uint32_t &fing) {
        #if DEBUG_F
        ++pure_cnt;
        #endif
        flow_id = (id[row][col] * table[counter[row][col] % PRIME_ID]) % PRIME_ID;
        if (use_fing) {
            fing = powMod32(counter[row][col], PRIME_FING - 2, PRIME_FING);
            fing = mulMod32(fingerprint[row][col], fing, PRIME_FING);
        }
        if (!(hash[row].run((char*)&flow_id, sizeof(uint32_t)) % entry_num == col))
            return false;
        if (use_fing && !(hash_fp->run((char*)&flow_id, sizeof(uint32_t)) % PRIME_FING == fing))
            return false;
        return true;
    }

    void display() {
        cout << " --- display --- " << endl;
        for (int i = 0; i < array_num; ++i) {
            for (int j = 0; j < entry_num; ++j) {
                if (counter[i][j]) {
                    cout << i << "," << j << ":" << counter[i][j] << endl;
                }
            }
        }
    }

    bool Decode(unordered_map<uint32_t, int> &result) {
        queue<int> *candidate = new queue<int> [array_num];
        uint32_t flow_id;
        uint32_t fing;

        vector<vector<bool>> processed(array_num);
        for (int i = 0; i < array_num; ++i) {
            processed[i].resize(entry_num);
            for (int j = 0; j < entry_num; ++j)
                processed[i][j] = false;
        }
        // display();

        // while (true) {
        //     bool pause = true;
        //     for (int i = 0; i < array_num; ++i)
        //         for (int j = 0; j < entry_num; ++j) {
        //             if (counter[i][j] == 0) {
        //                 processed[i][j] = true;
        //                 continue;
        //             }
        //             if (processed[i][j]) continue;
        //             if (verify(i, j, flow_id, fing)) {
        //                 pause = false;
        //                 processed[i][j] = true;
        //                 // result.insert(make_pair(flow_id, counter[i][j]));
        //                 result[flow_id] = counter[i][j];
        //                 for (int t = 0; t < array_num; ++t) {
        //                     if (t == i) continue;
        //                     uint32_t pos = hash[t].run((char*)&flow_id, sizeof(uint64_t)) % entry_num;
        //                     Delete_in_one_bucket(t, pos, i, j);
        //                 }
        //                 // display();
        //             }
        //         }
        //     if (pause)
        //         break;
        // }


        // first round
        for (int i = 0; i < array_num; ++i)
            for (int j = 0; j < entry_num; ++j) {
                if (counter[i][j] == 0) 
                    processed[i][j] = true;
                else if (verify(i, j, flow_id, fing)) { 
                    // find pure bucket
                    processed[i][j] = true;
                    result[flow_id] = counter[i][j];
                    // delete flow from other rows
                    for (int t = 0; t < array_num; ++t) {
                        if (t == i) continue;
                        uint32_t pos = hash[t].run((char*)&flow_id, sizeof(uint32_t)) % entry_num;
                        Delete_in_one_bucket(t, pos, i, j);
                        if (t < i)
                            candidate[t].push(pos);
                    }
                }
            }

        bool pause;
        while (true) {
            pause = true;
            for (int i = 0; i < array_num; ++i) {
                if (!candidate[i].empty()) pause = false;
                while (!candidate[i].empty()) {
                    int check = candidate[i].front();
                    candidate[i].pop();
                    if (processed[i][check]) continue;
                    if (counter[i][check] == 0) 
                        processed[i][check] = true;
                    else if (verify(i, check, flow_id, fing)) { 
                        // find pure bucket
                        processed[i][check] = true;
                        result[flow_id] = counter[i][check];
                        // delete flow from other rows
                        for (int t = 0; t < array_num; ++t) {
                            if (t == i) continue;
                            uint32_t pos = hash[t].run((char*)&flow_id, sizeof(uint32_t)) % entry_num;
                            Delete_in_one_bucket(t, pos, i, check);
                            candidate[t].push(pos);
                        }
                    }
                }
            }
            if (pause)
                break;
        }

        delete [] candidate;

        for (int i = 0; i < array_num; ++i)
            for (int j = 0; j < entry_num; ++j)
                if (!processed[i][j]) 
                    return false;        

        return true;
    }
};

#endif
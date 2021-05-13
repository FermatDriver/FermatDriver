#ifndef _RATE_TEST_H_
#define _RATE_TEST_H_
#include "fermat.h"
#include "lossradar.h"
#include "flowradar.h"
#include "generate_flows.h"
#include <chrono>
#include <fstream>

using namespace std;

class TestInsertRate {
    Fermat fermat_rehash1, fermat_rehash2;
    Fermat fermat_fing1, fermat_fing2;
    LossRadar lossradar1, lossradar2;
    FlowRadar flowradar1,flowradar2;
public:
    TestInsertRate(int _fing_mem, int _rehash_mem, int _lossr_mem, int _flowr_mem) :
        fermat_fing1(_fing_mem, true, 102), fermat_fing2(_fing_mem, true, 102), fermat_rehash1(_rehash_mem, false, 205), fermat_rehash2(_rehash_mem, false, 205),
        lossradar1(3, _lossr_mem, 349), lossradar2(3, _lossr_mem, 349), flowradar1(_flowr_mem, 3, 508), flowradar2(_flowr_mem, 3, 508) {}

    void insert_fermat_fing(const CDF_flows &data, ofstream &output) {
        auto start = chrono::high_resolution_clock::now();
        for (auto &p : data.flow_set) {
            for (uint16_t i = 0; i < p.second; ++i) 
                fermat_fing1.Insert_one(p.first);
            if (data.dropped_set.count(p.first)) {
                for (uint16_t i = data.dropped_set.at(p.first); i < p.second; ++i)
                    fermat_fing2.Insert_one(p.first);
            }
            else {
                for (uint16_t i = 0; i < p.second; ++i)
                    fermat_fing2.Insert_one(p.first);
            }
        }
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << (double) (2 * data.packet_num - data.dropped_num) / duration.count();
    }
    
    void insert_fermat_rehash(const CDF_flows &data, ofstream &output) {
        auto start = chrono::high_resolution_clock::now();
        for (auto &p : data.flow_set) {
            for (uint16_t i = 0; i < p.second; ++i) 
                fermat_rehash1.Insert_one(p.first);
            if (data.dropped_set.count(p.first)) {
                for (uint16_t i = data.dropped_set.at(p.first); i < p.second; ++i)
                    fermat_rehash2.Insert_one(p.first);
            }
            else {
                for (uint16_t i = 0; i < p.second; ++i)
                    fermat_rehash2.Insert_one(p.first);
            }
        }
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << (double) (2 * data.packet_num - data.dropped_num) / duration.count();
    }

    void insert_lossradar(const CDF_flows &data, ofstream &output) {
        auto start = chrono::high_resolution_clock::now();
        for (auto &p : data.flow_set) {
            for (uint16_t i = 0; i < p.second; ++i) 
                lossradar1.Insert_id_seq(p.first, i);
            if (data.dropped_set.count(p.first)) {
                for (uint16_t i = data.dropped_set.at(p.first); i < p.second; ++i)
                    lossradar2.Insert_id_seq(p.first, i);
            }
            else {
                for (uint16_t i = 0; i < p.second; ++i)
                    lossradar2.Insert_id_seq(p.first, i);
            }
        }
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << (double) (2 * data.packet_num - data.dropped_num) / duration.count(); 
    }

    void insert_flowradar(const CDF_flows &data, ofstream &output) {
        auto start = chrono::high_resolution_clock::now();
        for (auto &p : data.flow_set) {
            for (uint16_t i = 0; i < p.second; ++i) 
                flowradar1.Insert(p.first);
            if (data.dropped_set.count(p.first)) {
                for (uint16_t i = data.dropped_set.at(p.first); i < p.second; ++i)
                    flowradar2.Insert(p.first);
            }
            else {
                for (uint16_t i = 0; i < p.second; ++i)
                    flowradar2.Insert(p.first);
            }
        }
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << (double) (2 * data.packet_num - data.dropped_num) / duration.count();
    }
};

class TestDecodeRate {
    Fermat fermat_rehash;
    Fermat fermat_fing;
    LossRadar lossradar;
    FlowRadar flowradar1,flowradar2;
public:
    TestDecodeRate(int _fing_mem, int _rehash_mem, int _lossr_mem, int _flowr_mem) :
        fermat_fing(_fing_mem, true, 102), fermat_rehash(_rehash_mem, false, 205),
        lossradar(3, _lossr_mem, 349), flowradar1(_flowr_mem, 3, 508), flowradar2(_flowr_mem, 3, 508) {}

    void insert_flow(const CDF_flows &data) {
        for (auto p : data.flow_set) {
            for (uint16_t i = 0; i < p.second; ++i)
                flowradar1.Insert(p.first);
            if (data.dropped_set.count(p.first)) {
                fermat_fing.Insert(p.first, data.dropped_set.at(p.first));
                fermat_rehash.Insert(p.first, data.dropped_set.at(p.first));
                lossradar.Insert_range_data(p.first, data.dropped_set.at(p.first));
                for (uint16_t i = data.dropped_set.at(p.first); i < p.second; ++i)
                    flowradar2.Insert(p.first);
            }
            else {
                for (uint16_t i = 0; i < p.second; ++i)
                    flowradar2.Insert(p.first);
            }
        }
    }

    void decode(const CDF_flows &data, ofstream &output) {
        int flow_sum = data.dropped_set.size();

        int decoded_flow_cnt = 0;
        unordered_map<uint32_t, int> res, res2;
        
        auto start = chrono::high_resolution_clock::now();
        fermat_fing.Decode(res);
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << duration.count() << "\t";

        for (auto &p : data.dropped_set) {
            if (res.count(p.first) != 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
        }
        cout << "fermat_with_fing accuracy: " << (double)decoded_flow_cnt / flow_sum << endl;
        cout << fermat_fing.pure_cnt << endl;

        res.clear();
        decoded_flow_cnt = 0;

        start = chrono::high_resolution_clock::now();
        fermat_rehash.Decode(res);
        end = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << duration.count() << "\t";

        for (auto &p : data.dropped_set) {
            if (res.count(p.first) != 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
        }
        cout << "fermat_with_rehash accuracy: " << (double)decoded_flow_cnt / flow_sum << endl;
        cout << fermat_rehash.pure_cnt << endl;

        res.clear();
        decoded_flow_cnt = 0;

        start = chrono::high_resolution_clock::now();
        lossradar.Decode(res);
        end = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << duration.count() << "\t";

        for (auto &p : data.dropped_set) {
            if (res.count(p.first) != 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
        }
        cout << "lossradar accuracy: " << (double)decoded_flow_cnt / flow_sum << endl;

        res.clear();
        decoded_flow_cnt = 0;
        
        start = chrono::high_resolution_clock::now();
        flowradar1.SingleDecode(res);
        flowradar2.SingleDecode(res2);
        end = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(end - start);
        output << duration.count() << "\t";
        
        for (auto &p : data.dropped_set) {
            if (res2.count(p.first) == 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
            else if (res[p.first] - res2[p.first] == p.second)
                ++decoded_flow_cnt;
        }
        cout << "flowradar accuracy: " << (double)decoded_flow_cnt / flow_sum << endl;  
        cout << flowradar1.pure_cnt + flowradar2.pure_cnt << endl;
    }
};

#endif
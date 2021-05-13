#include "generate_flows.h"
#include "fermat.h"
#include "lossradar.h"
#include "flowradar.h"
#include <fstream>

using namespace std;

class TestDecode {
    int memory_size;
    Fermat fermat_rehash, fermat_fing;
    LossRadar lossradar;
    FlowRadar flowradar1, flowradar2;

public:
    TestDecode(int _mem) : memory_size(_mem), fermat_fing(_mem, true, 102), fermat_rehash(_mem, false, 205), 
        lossradar(3, _mem, 349), flowradar1(_mem, 3, 508), flowradar2(_mem, 3, 508) {}

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
        // cout << "--- mem: " << memory_size << " --- " << endl;
        output << memory_size << "\t";

        int decoded_flow_cnt = 0;
        unordered_map<uint32_t, int> res, res2;

        fermat_fing.Decode(res);

        for (auto &p : data.dropped_set) {
            if (res.count(p.first) != 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
            // else {
            //     cout << p.first << " " << p.second << endl;
            // }
        }
        output << (double)decoded_flow_cnt / flow_sum << "\t";

        res.clear();
        decoded_flow_cnt = 0;

        fermat_rehash.Decode(res);
        for (auto &p : data.dropped_set) {
            if (res.count(p.first) != 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
            // else 
            //     cout << p.first << " " << p.second << " " << data.dropped_set.at(p.first) << endl;
        }
        output << (double)decoded_flow_cnt / flow_sum << "\t";

        res.clear();
        decoded_flow_cnt = 0;

        lossradar.Decode(res);
        for (auto &p : data.dropped_set) {
            if (res.count(p.first) != 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
        }
        output << (double)decoded_flow_cnt / flow_sum << "\t";

        res.clear();
        decoded_flow_cnt = 0;

        flowradar1.SingleDecode(res);
        flowradar2.SingleDecode(res2);
        for (auto &p : data.dropped_set) {
            if (res2.count(p.first) == 0 && res[p.first] == p.second)
                ++decoded_flow_cnt;
            else if (res[p.first] - res2[p.first] == p.second)
                ++decoded_flow_cnt;
        }

        output << (double)decoded_flow_cnt / flow_sum << endl;
    }
};


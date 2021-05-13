#ifndef _GENERATE_FLOWS_H_
#define _GENERATE_FLOWS_H_

#include <map>
#include <random>
#include <unordered_map>
#include <iostream>

using namespace std;

// DCTCP_CDF
static const map<double, int> mp = {
{0, 0}, 
{0.15, 10}, 
{0.2, 20}, 
{0.3, 30},
{0.4, 50},
{0.53, 80},
{0.6, 200},
{0.7, 1e+03},
{0.8, 2e+03},
{0.9, 5e+03},
{0.97, 1e+04},
{1, 3e+04}
};

int get_stream_size(double d) {
    auto it = mp.lower_bound(d);
    auto next = it;
    if(it != mp.begin()) it --;
    double k = (next->second - it->second) / (next->first - it->first);
    return it->second + ((d - it->first) * k);
}

double _rand_double() {
    static default_random_engine e;
    uniform_real_distribution<double> u(0.0, 1.0);
    return u(e);
}

void loadCAIDA18(const char *filename, unordered_map<uint64_t, uint16_t> &data) {
    printf("Open %s \n", filename);
    FILE* pf = fopen(filename, "rb");
    if(!pf){
        printf("%s not found!\n", filename);
        exit(-1);
    }
    char trace[30];
    uint64_t flow_id; 
    while(fread(trace, 1, 21, pf)) {
        flow_id = *(uint64_t*) (trace); 
        flow_id &= (0x3fffffffffffffff);

        if (data.count(flow_id) == 0) 
            data[flow_id] = 1;
        else 
            ++data[flow_id];
    }
    fclose(pf);
}

struct CDF_flows
{
    int setting;
    uint32_t dropped_num, packet_num;
    unordered_map<uint32_t, uint16_t> flow_set, dropped_set;

    CDF_flows(int _set) : setting(_set), dropped_num(0), packet_num(0) {}

    void load_data(const char* filename) {
        unordered_map<uint64_t, uint16_t> data;
        loadCAIDA18(filename, data);

        if (setting == 0) {
            int cnt = 0;
            for (auto &p : data) {
                uint16_t flow_size = get_stream_size(_rand_double());
                while (flow_size == 0) 
                    flow_size = get_stream_size(_rand_double());
                
                flow_set[p.first] = flow_size;
                packet_num += flow_size;
                if (cnt < 100) {
                    dropped_set[p.first] = ceil((double)flow_size * 0.05);
                    dropped_num += dropped_set[p.first];
                }  
                ++cnt;
                if (cnt >= 1000)
                    break;
            }
        }
        else if (setting == 1) {
            int cnt = 0;
            for (auto &p : data) {
                uint16_t flow_size = get_stream_size(_rand_double());
                while (flow_size == 0) 
                    flow_size = get_stream_size(_rand_double());

                flow_set[p.first] = flow_size;
                packet_num += flow_size;
                if (cnt < 100) {
                    dropped_set[p.first] = flow_size;
                    dropped_num += flow_size;
                }
                ++cnt;
                if (cnt >= 10000)
                    break;
            }
        }
    }

    void generate_sim_data() {
        if (setting == 0) {
            for (uint32_t i = 0; i < 1000; ++i) {
                uint16_t flow_size = get_stream_size(_rand_double());
                while (flow_size == 0) 
                    flow_size = get_stream_size(_rand_double());

                flow_set[i] = flow_size;
                packet_num += flow_size;
                if (i < 100) {
                    dropped_set[i] = ceil(flow_size * 0.05);
                    dropped_num += dropped_set[i];
                }
            }
        }
        else if (setting == 1) {
            for (uint32_t i = 0; i < 10000; ++i) {
                uint16_t flow_size = get_stream_size(_rand_double());
                while (flow_size == 0) 
                    flow_size = get_stream_size(_rand_double());
                
                flow_set[i] = flow_size;
                packet_num += flow_size;
                if (i < 100) {
                    dropped_set[i] = flow_size;
                    dropped_num += flow_size;
                }
            }
        }
    }
};



#endif
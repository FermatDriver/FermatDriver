#include "decode_test.h"

using namespace std;


int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "./decode_test setting" << endl;
        return 0;
    }

    CDF_flows data(atoi(argv[1]));
    string output_file = "accuracy-" + string(argv[1]) + ".xls";
    ofstream output(output_file);
    data.generate_sim_data();

    cout << "dropped num: " << data.dropped_num << " packet num: " << data.packet_num << endl;

    output << "memory\tfermat(fp)\tfermat\tlossradar\tflowradar" << endl;

    for (int mem = 100; mem < 10000000; mem *= 1.1) {
        TestDecode test(mem);
        test.insert_flow(data);
        test.decode(data, output);
    }

    output.close();
    cout << "finish" << endl;

    return 0;
}
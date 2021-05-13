#include "rate_test.h"

using namespace std;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cout << "./rate_test setting" << endl;
        return 0;
    }

    CDF_flows data(atoi(argv[1]));
    data.generate_sim_data();

    string output_decode_file = "decode-rate-" + string(argv[1]) + ".xls";
    ofstream output_decode(output_decode_file);

    output_decode << "fermat(fp)\tfermat\tlossradar\tflowradar" << endl;
    TestDecodeRate test_decode(2356, 1158, 1775254, 351228);
    test_decode.insert_flow(data);
    test_decode.decode(data, output_decode);

    string output_insert_file = "insert-rate-" + string(argv[1]) + ".xls";
    ofstream output_insert(output_insert_file);

    output_insert << "fermat(fp)\tfermat\tlossradar\tflowradar" << endl;
    TestInsertRate test_insert(2356, 1158, 1775254, 351228);
    test_insert.insert_fermat_fing(data, output_insert);
    output_insert << "\t";
    test_insert.insert_fermat_rehash(data, output_insert);
    output_insert << "\t";
    test_insert.insert_lossradar(data, output_insert);
    output_insert << "\t";
    test_insert.insert_flowradar(data, output_insert);
    output_insert << endl;

    output_insert.close();

    return 0;
}
## Simulation Experiments on Fermat Sketch

* We compare our Fermat sketch with FlowRadar and LossRadar, in the aspects of decode success rate and processing speed.

### File Description

* the code for three algorithms are included in the following files seperately:
  * `fermat.h` is the code for Fermat Sketch.
  * `flowradar.h` is the code for FlowRadar.
  * `lossradar.h` is the code for LossRadar.
* `generate_flows.h` generate flows according to widely-used traffic distribution DCTCP.
* `decode_test.h`, `decode_test.cc` measure the decode success rate for three algorithms.
* `rate_test.h`, `rate_test.cc` measure the processing speed for three algorithms.

### Run

1. `make`
2. For decode success rate experiments, run `./decode_test setting`
3. For processing speed experiments, run `./rate_test setting`

* Here 'setting' can be 0 or 1,
  * 0 denote the setting that 1000 flows in total, where 10% of flows drop 5% packets.
  * 1 denote the setting that 10000 flows in total, where 1% of flows drop all packets.

 


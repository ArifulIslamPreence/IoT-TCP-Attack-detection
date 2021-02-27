# iot-traffic-analysis

PCAP dataset can be downloaded from here --> https://iotanalytics.unsw.edu.au/attack-data

Flow generators Argus and Tranalyzer were used to reduce the raw pcap packets to flows.

## Extracting Flows from PCAPs
### Tranalyzer
```
# Run these bash commands to generate tranalyzer flow files from pcap files
# WARNING! this may take a while
for f in benign/pcap/*.pcap; do t2 -r "$f" -w benign/tran/. & done
for f in attack/pcap/*.pcap; do t2 -r "$f" -w attack/tran/. & done
```
### Argus
```
#TODO
```

## Project Structure
In order to run this script, the following project structure is expected

```
iot-traffic-analysis/    # project root (where jupyter is running)
    benign/
        pcap/
          18-05-28.pcap
          18-05-29.pcap
          ...
        tran/
          18-05-28_flows.pcap
          18-05-28_headers.pcap
          ...
        argus/
          ...
    attack/
        pcap/
          ...
        tran/
          ...
        argus/
          ...
```


# Detection of malicious IoT Traffic
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
# Run these bash commands to generate Argus flows
sudo /usr/local/sbin/argus -mJAZR -r {pcap_file} -w output.argus

# To get output in Unix time 
RA_PRINT_UNIX_TIME=yes

# Finally extract the flow information
ra -u -s +1dur dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz,label -c ',' -r output.argus > output.csv

# Other Argus Commands for reference
ra -M uni -s stime,dur,flgs,proto,saddr,sport,smac,dir,daddr,dport,dmac,pkts,bytes,state -c ',' -r eth0_clustered.arg > eth3.csv
ra -s Dur,Proto,SrcAddr,SrcMac,Sport,Dir,DstAddr,DstMac,Dport,RunTime,Mean,Sum,Min,Max,sTos,dTos,TotPkts,SrcPkts,DstPkts,sTtl,dTtl,TotAppByte,TotBytes,SAppBytes,DstBytes,DAppBytes,Load,SrcLoad,DstLoad,Loss,SrcLoss,DstLoss,Loss.1,Rate,SIntPkt,SIntPktAct,SIntPktIdl,DIntPkt,DIntPktAct,DIntPktIdl,SrcJitter,DstJitter,sMeanPktSz,dMeanPktSz,sMaxPktSz,dMaxPktSz,sMinPktSz,dMinPktSz -c ',' -r eth0_clustered.arg > eth1.csv
ra -M uni -s dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz -c ',' -r eth0_clustered.arg > eth4.csv
ralabel
ra -M uni -s dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz,label -c ',' -r eth0_clustered.arg > eth5.csv
ra -s +1dur dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz,label -c ',' -r mon_hour.argus > mon.csv
ra -s +1dur dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz,label -c ',' -r zeus.argus > th.csv
ra -s +1dur dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz,label -c ',' -r wed.argus > wed.csv
ra -s dur,flgs,proto,saddr,smac,sport,dir,daddr,dmac,dport,runtime,mean,sum,min,max,stos,dtos,pkts,spkts,dpkts,sttl,dttl,appbytes,bytes,sappbytes,dbytes,dappbytes,load,sload,dload,loss,sloss,dloss,rate,sintpkt,sintpktact,sintpktidl,dintpkt,dintpktact,dintpktidl,sjit,djit,smeansz,dmeansz,smaxsz,dmaxsz,sminsz,dminsz,label -c ',' -r wed.argus > wed1.csv
sudo /usr/local/sbin/argus -mJAZR -r mon_hour.pcapng -w zeus.argus
ra -s stime,dur,flgs,proto,saddr,sport,smac,dir,daddr,dport,dmac,pkts,bytes,state -c ',' -r zeus.argus > eth2.csv
sudo /usr/local/sbin/argus -mJAZR -r tue_hour.pcap -w th.argus
sudo /usr/local/sbin/argus -mJAZR -r tue_hour.pcaping -w th.argus
sudo /usr/local/sbin/argus -mJAZR -r tue_hour.pcapng -w th.argus
ra -s stime,dur,flgs,proto,saddr,sport,smac,dir,daddr,dport,dmac,pkts,bytes,state -c ',' -r zeus.argus > th.csv
ra -s stime,dur,flgs,proto,saddr,sport,smac,dir,daddr,dport,dmac,pkts,bytes,state -c ',' -r th.argus > th.csv
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


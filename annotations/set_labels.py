import os
from datetime import datetime


devices_ip = []
devices_mac = []

with open('../device_info.csv', 'r') as f:
  for line in f.readlines()[1:]:
    values = line.split(',')
    devices_mac.append(values[0])
    devices_ip.append(values[1])

times = []
for filename in os.listdir(os.getcwd()):
  
  with open(os.path.join(os.getcwd(), filename), 'r') as f:
    for line in f.readlines():
      values = line.strip().split(',')

      try:
        start_value = float(values[0])
        end_value = float(values[1])
        times.append((start_value, end_value))
      except:
        continue

print("Done with annotations")

times_pcap = []
flows = []

with open('/home/faizan/dalhousie/181021-3.csv', 'r') as f:
  for i, line in enumerate(f.readlines()[1:]):
    values = line.strip().split(',')
    strt_time = float(values[0])
    dur = float(values[1])
    end_time = strt_time + dur

    if values[4] in devices_ip or values[19] in devices_ip:
      times_pcap.append((strt_time, end_time))
    if values[4] in devices_mac or values[19] in devices_mac:
      times_pcap.append((strt_time, end_time))

    flows.append(values)


times.sort(key=lambda tup: tup[0])


times_pcap.sort(key=lambda tup: tup[0])

minm = times_pcap[0][0]
maxm = times_pcap[-1][0]
times_in_data = []

print(minm)

for t1, t2 in times:
  if t1 > minm and t2 < maxm:
    print(t1, t2)
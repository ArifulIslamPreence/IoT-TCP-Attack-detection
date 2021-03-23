import sys
import os
import glob
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt 
import torch
print(f"CUDA Available: {torch.cuda.is_available()}")
time_to_date = lambda t: datetime.utcfromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')

print("Current Directory:" + os.getcwd())
file_pattern = '*_flows.txt' # Use all pcap files
# file_pattern = '18-06-09_flows.txt'
glob_path = os.path.join('/users/grad/fali', 'benign/tran', file_pattern)
file_list = glob.glob(glob_path)

li = []
for filepath in file_list:
    df = pd.read_csv(filepath, index_col=None, header=0, delimiter='\t')
    li.append(df)

benign_flows = pd.concat(li, axis=0, ignore_index=True)

print("Current Directory:" + os.getcwd())
file_pattern = '*_flows.txt' # Use all pcap files
# file_pattern = '18-06-01_flows.txt'
glob_path = os.path.join('/users/grad/fali', 'attack/tran', file_pattern)
file_list = glob.glob(glob_path)

li = []
for filepath in file_list:
    df = pd.read_csv(filepath, index_col=None, header=0, delimiter='\t')
    li.append(df)

mixed_flows = pd.concat(li, axis=0, ignore_index=True)
all_flows=pd.concat([benign_flows, mixed_flows], axis=0)
# Load device_info from file
mac_to_filename = lambda s: f"{s.lower().replace(':', '')}.csv"

filepath = "/users/grad/fali/iot-traffic-analysis/device_info.csv"
device_info = pd.read_csv(filepath, index_col=None, delimiter=',')
device_info['annotation_file'] = device_info['mac'].map(mac_to_filename)
file_pattern = '*.csv'
glob_path = os.path.join('/users/grad/fali/iot-traffic-analysis', 'annotations', file_pattern)
file_list = glob.glob(glob_path)

li = []
for filepath in file_list:
    print(f"loading {filepath}")
    df = pd.read_csv(filepath, index_col=None, delimiter=',', header=0, names=[
      'start_time', 'end_time', 'description', 'attack_type'])

    filename = os.path.basename(filepath)
    df['annotation_file'] = filename
    li.append(df)

all_known_attacks = pd.concat(li, axis=0, ignore_index=True)
# Convert time units to match tranalyzer
all_known_attacks.sort_values(by=['start_time'], inplace=True, ignore_index=True)
all_known_attacks["duration"] = all_known_attacks['end_time'] - all_known_attacks['start_time']

# Enrich attack meta-data with device meta-data
all_known_attacks = all_known_attacks.set_index('annotation_file').join(device_info.set_index('annotation_file'))
last_attack_endtime = max(all_known_attacks['end_time'])
last_flow_endtime = max(mixed_flows['timeLast'])

print(f"last known attack ended at {time_to_date(last_attack_endtime)}")
# TODO - investigate why the last attack happens on Oct 25, but there are two more days of mixed traffic (Oct 26, Oct 27)

# Filter out attacks that happened outside our current dataset scope
known_attacks = all_known_attacks[all_known_attacks['end_time'] <= last_flow_endtime]
print(f"Using {len(known_attacks)} of {len(all_known_attacks)} known attacks")

# Apply IP and mac adress filters
attacker_ips = known_attacks.ip.unique()
attacker_macs = known_attacks.mac.unique()
attack_windows = [tuple(time_range) for time_range in known_attacks[['start_time', 'end_time']].values]
matches_attack_address = (mixed_flows.srcIP.isin(attacker_ips)) | (mixed_flows.srcMac.isin(attacker_macs)) | (mixed_flows.dstIP.isin(attacker_ips)) | (mixed_flows.dstMac.isin(attacker_macs))

# Apply attack window filters (capture flows that occured within a known attack)
attack_window_filters = [(attack.start_time <= mixed_flows.timeFirst) & (attack.end_time <= mixed_flows.timeLast)
                         for i, attack in known_attacks.iterrows()]
in_any_attack_window = np.logical_or.reduce(attack_window_filters)

# Label traffic as attack or benign
# TODO - make sure only malicous flows are being captured by our filters

mixed_flows['is_attack'] = False
mixed_flows.loc[matches_attack_address & in_any_attack_window, 'is_attack'] = True

print(f"Flow Counts ~ Mixed: {len(mixed_flows)}, Benign: {(~mixed_flows.is_attack).sum()}, Attack: {(mixed_flows.is_attack).sum()}")
print("Listing features with a single uniform value (no information)")
print("Feature: unique value count")
print(all_flows.nunique()[all_flows.nunique() <= 1])

# Features that have uniform values for our dataset
no_info_features = ['ethVlanID', 'macStat', 'minIAT', 'tcpMPAID', 'icmpTmGtw']

# Features which will not be used
pointless_features = ['timeFirst', 'timeLast', 'dstPort', 'srcPort', 'dstIP',
                      'dstMac', 'srcIP', 'srcMac', 'srcMac_dstMac_numP']

# Non-decimal features categorized by data-type
hex_features = ['flowStat', 'tcpFStat', 'ipTOS', 'ipFlags', 'ethType',
                 'tcpStates', 'icmpStat', 'tcpAnomaly',
                'tcpFlags',  'tcpMPF', 'tcpMPTBF', 'tcpMPdssF', 'tcpOptions']

string_features = ['%dir', 'hdrDesc', 'srcManuf_dstManuf', 'dstPortClass',
                   'srcIPCC', 'dstIPCC', 'dstIPOrg', 'srcIPOrg', 'numHdrs']


# Not sure what to make of these - more research required
underscore_features = ['ipOptCpCl_Num', 'icmpBFTypH_TypL_Code', 'ip6OptHH_D', 'ip6OptCntHH_D']

# Features we will use
features = ['flowInd', 'duration', 'numHdrDesc',
            'l4Proto', 'macPairs', 'dstPortClassN', 'numPktsSnt', 'numPktsRcvd',
            'numBytesSnt', 'numBytesRcvd', 'minPktSz', 'maxPktSz', 'avePktSize', 'stdPktSize', 'pktps', 'bytps',
            'pktAsm', 'bytAsm', 'ipMindIPID', 'ipMaxdIPID', 'ipMinTTL', 'ipMaxTTL', 'ipTTLChg', 'ipOptCnt',
            'tcpPSeqCnt', 'tcpSeqSntBytes', 'tcpSeqFaultCnt', 'tcpPAckCnt', 'tcpFlwLssAckRcvdBytes', 'tcpAckFaultCnt',
            'tcpInitWinSz', 'tcpAveWinSz', 'tcpMinWinSz', 'tcpMaxWinSz', 'tcpWinSzDwnCnt', 'tcpWinSzUpCnt',
            'tcpWinSzChgDirCnt', 'tcpOptPktCnt', 'tcpOptCnt', 'tcpMSS', 'tcpWS', 'tcpTmS', 'tcpTmER', 'tcpEcI',
            'tcpBtm', 'tcpSSASAATrip', 'tcpRTTAckTripMin', 'tcpRTTAckTripMax', 'tcpRTTAckTripAve',
            'tcpRTTAckTripJitAve', 'tcpRTTSseqAA', 'tcpRTTAckJitAve', 'icmpTCcnt', 'icmpEchoSuccRatio', 'icmpPFindex',
            'connSip', 'connDip', 'connSipDip', 'connSipDprt', 'connF',  'aveIAT', 'maxIAT',
                'stdIAT', 'tcpISeqN', 'tcpUtm', 'tcpWinSzThRt']

unused_features = no_info_features + pointless_features + hex_features + string_features + underscore_features
all_features = features + unused_features
labels = ['is_attack']
mixed_flows[features + labels]


import os
import torch
import csv
import random
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn import preprocessing
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, roc_auc_score
from sklearn.model_selection import train_test_split

import torch.nn as nn
import torch.optim as optim
import torch.utils.data as data_utils

#constant declaration
NUM_EPOCHS = 5
LEARNING_RATE = 1e-3
BATCH_SIZE = 30

# For full dataset, run tran_feature_selection notebook before this one
# For small subset of data, run tran_sample_preprocessing notebook beofore this one (ideal for testing model on CPU)
dim = len(features)

#TODO look into scalars vs normalizers --> https://datascience.stackexchange.com/questions/45900/when-to-use-standard-scaler-and-when-normalizer

normalizer = preprocessing.Normalizer(norm="l2")
normalized_train = normalizer.fit_transform(benign_flows[features]) #axis?
train_X = pd.DataFrame(normalized_train, columns = features)

normalized_test = normalizer.transform(mixed_flows[features])
test_X = pd.DataFrame(normalized_test, columns = features)
test_y = mixed_flows.is_attack

#dataset loading
train_tensor = torch.tensor(train_X.values.astype(np.float32))
train_loader = torch.utils.data.DataLoader(train_tensor, batch_size = BATCH_SIZE, shuffle = True)

class Autoencoder(nn.Module):
    def __init__(self):
        super(Autoencoder, self).__init__()
        # encoder
        self.enc1 = nn.Linear(in_features=dim, out_features=int(dim/2))
        self.enc2 = nn.Linear(in_features=int(dim/2), out_features=int(dim/4))
        self.enc3 = nn.Linear(in_features=int(dim/4), out_features=int(dim/8))

        # decoder
        self.dec1 = nn.Linear(in_features=int(dim/8), out_features=int(dim/4))
        self.dec2 = nn.Linear(in_features=int(dim/4), out_features=int(dim/2))
        self.dec3 = nn.Linear(in_features=int(dim/2), out_features=dim)

    def forward(self, x):
#         x = F.relu(self.enc1(x))
#         x = F.relu(self.enc2(x))
#         x = F.relu(self.enc3(x))

#         x = F.relu(self.dec1(x))
#         x = F.relu(self.dec2(x))
#         x = F.relu(self.dec3(x))

        #sigmoid activation
        x = torch.sigmoid(self.enc1(x))
        x = torch.sigmoid(self.enc2(x))
        x = torch.sigmoid(self.enc3(x))

        x = torch.sigmoid(self.dec1(x))
        x = torch.sigmoid(self.dec2(x))
        x = torch.sigmoid(self.dec3(x))
        return x
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
net = Autoencoder()
net.to(device)
optimizer = optim.Adam(net.parameters(), lr=LEARNING_RATE)


#Trainning model

loss_function = nn.BCELoss()  # Alternative loss functions - BCEWithLogitsLoss(), MSELoss()

import pickle

train_loss = []
for epoch in range(NUM_EPOCHS):
    running_loss = 0.0
    print(f"epoch: {epoch}")
    for data in train_loader:
        input_data = data.to(device=device)
        optimizer.zero_grad()
        output = net(input_data).to(device=device)                  # output is the reconstruced x
        loss = loss_function(output, input_data).to(device=device)  # input_data should be the target variable
        loss.backward()
        optimizer.step()
        running_loss += loss.item()

    loss = running_loss / len(train_loader)
    train_loss.append(loss)

#     if epoch % 5 == 0:
    print('Epoch {} of {}, Train Loss: {:.3f}'.format(
      epoch+1, NUM_EPOCHS, loss))
    pickle.dump(net, open("model", 'wb'))

print("Completed training with final loss {:.3f}".format(train_loss[-1]))

_, ax = plt.subplots(1,1,figsize=(15,10))
plt.xlabel("epochs")
plt.ylabel("loss value ")
ax.set_title('Loss graph')
ax.plot(train_loss)

# Calculate reconstruction loss for test partition (mixed flow data)
test_loss = []
net.eval()
test_tensor = torch.tensor(test_X.values.astype(np.float32))
with torch.no_grad():
    for i in range(len(test_X)):
        input = test_tensor[i].to(device=device)
        output = net(input).to(device=device)
        loss = loss_function(output, input).to(device=device)
        test_loss.append(loss.item())

fpr, tpr, thresholds = roc_curve(y_true=test_y.astype(int), y_score=test_loss, pos_label=1)
auc = roc_auc_score(y_true=test_y.astype(int),  y_score=test_loss)
plt.figure(figsize=(10, 10))
plt.plot([0,1], [0,1], linestyle="--") # plot random curve
plt.plot(fpr, tpr, marker=".", label=f"AUC = {auc}")
plt.title("ROC Curve")
plt.ylabel("True Positive Rate")
plt.xlabel("False Positive Rate")
plt.legend(loc="lower right")

ranked_thresholds = sorted(list(zip(np.abs(tpr - fpr), thresholds)), key=lambda i: i[0], reverse=True)
attack_threshold = ranked_thresholds[0][1]
print(f"Attack Threshold: {attack_threshold}")


test_results = test_y.to_frame().astype(bool)
test_results['loss'] = pd.Series(test_loss, index=test_results.index)
test_results['is_attack_prediction'] = test_results.loss > attack_threshold

conf_matrix = confusion_matrix(test_results.is_attack, test_results.is_attack_prediction)
plt.figure()
sns.heatmap(conf_matrix, annot=True, annot_kws={"size": 16}, fmt='g')
plt.title('Attack Threshold Classification - Confusion Matrix')
print(classification_report(test_results.is_attack, test_results.is_attack_prediction, target_names=["benign", "attack"]))

fig, (benign_ax, attack_ax) = plt.subplots(nrows=2, sharex=True, figsize=(20, 4))
fig.suptitle('Loss Projection with Attack Threshold')
fig.subplots_adjust(hspace=0.02)
attack_loss_points = [(i, 'attack') for i in test_results[test_results['is_attack'] == True].loss]
benign_loss_points = [(i, 'benign') for i in test_results[test_results['is_attack'] == False].loss]
benign_ax.scatter(*zip(*benign_loss_points), label="benign", color=['blue'], alpha=0.01)
attack_ax.scatter(*zip(*attack_loss_points), label="attack", color=['red'], alpha=0.01)
for ax in (benign_ax, attack_ax):
  ax.axvline(attack_threshold, 0.0, 10, color='purple')
  ax.legend()
  ax.grid(True)
plt.show()

sns.displot(test_results.loss, bins=100, kde=True, color='purple', height=6, aspect=16/6)
plt.axvline(attack_threshold, 0.0, 10, color='r')
plt.title('Loss Distribution')

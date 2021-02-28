import panda as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import torchvision
import AE

torch.backends.cudnn.benchmark = False
torch.backends.cudnn.deterministic = True

batch_size = 100
epoch = 20
lr = .03

train_dataset = ""

tr_loader = torch.utils.data.DataLoader(train_dataset, batch_size= batch_size, shuffle=False)


#  if gpu available
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

model = AE(input_shape= "here comes the 1D feature count").to(device)

optimizer = optim.Adam(model.parameters(), lr=learning_rate)

criterion = nn.MSELoss()

for epoch in range(epochs):
    loss = 0
    for batch_features, _ in tr_loader:

        batch_features = batch_features.view(-1,"").to(device)
        optimizer.zero_grad()

        outputs = model(batch_features)
        
        train_loss = criterion(outputs, batch_features)
        
        train_loss.backward()
        optimizer.step()
        loss += train_loss.item()
    
    loss = loss / len(tr_loader)
    
    print("epoch : {}/{}, loss = {:.3f}".format(epoch + 1, epochs, loss))


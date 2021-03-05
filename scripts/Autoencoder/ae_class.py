import panda as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import torchvision

class AE(nn.Module):
    def __init__(self, **kwargs):
        super().__init__()
        self.encoder_hidden_layer = nn.Linear(
            in_features=kwargs["input_shape"], out_features=
        )
        self.encoder_output_layer = nn.Linear(
            in_features=, out_features=
        )
        self.decoder_hidden_layer = nn.Linear(
            in_features=, out_features=
        )
        self.decoder_output_layer = nn.Linear(
            in_features=, out_features=kwargs["input_shape"]
        )

    def forward(self, features):
        activation = self.encoder_hidden_layer(features)
        activation = torch.relu(activation)
        code = self.encoder_output_layer(activation)
        code = torch.sigmoid(code)
        activation = self.decoder_hidden_layer(code)
        activation = torch.relu(activation)
        activation = self.decoder_output_layer(activation)
        reconstructed = torch.sigmoid(activation)
        return reconstructed

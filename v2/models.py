#!/usr/bin/python3
from typing import Type
# local modules
from L2_switch_client import L2SwitchClient
from des_3028_client import DES_3028_Client
from dgs_1210_client import DGS_1210_28_ME_B12_Client

# dictionary to match switch model names with their child classes
SWITCH_MODELS_MAP: dict[str, Type[L2SwitchClient]] = {
    "DES-3028": DES_3028_Client,
    "DGS-1210-28/ME/B2": DGS_1210_28_ME_B12_Client
}
import pandas as pd
from scapy.all import PcapReader
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from collections import Counter
import hashlib

print("All base imports loaded.")
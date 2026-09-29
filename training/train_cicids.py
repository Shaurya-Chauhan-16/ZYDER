"""ZYDER convenience script: Train on CICIDS2017."""
from training.train import train

if __name__ == "__main__":
    train(dataset="cicids", config_path="config/config.yaml", mode="native")

"""ZYDER convenience script: Train on UNSW-NB15."""
from training.train import train

if __name__ == "__main__":
    train(dataset="unsw", config_path="config/config.yaml", mode="native")

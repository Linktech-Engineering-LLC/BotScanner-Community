import sys
import json
import yaml
import datetime
from pathlib import Path
from BotScanner.loader import ConfigResolver, ConfigLoader

def load_yaml_file() -> dict:
    # Instantiate loader with context and config directory
    loader = ConfigLoader()

    # Access the merged config (already resolved by ConfigResolver)
    cfg = loader.merged
    resolver = ConfigResolver(cfg)
    resolved_cfg = resolver.resolve()    
    return resolved_cfg

def write_dat_file(cfg: dict, chose: str="json") -> Path:
    basename = Path(sys.argv[0]).stem
    data_dir = Path(cfg["paths"]["data_dir"])
    data_dir.mkdir(parents=True, exist_ok=True)
    datestamp = datetime.datetime.now().strftime("%Y%m%d")
    file_path = data_dir / f"{basename}_{datestamp}"
    # Metadata banner
    header = {
        "_meta": {
            "script": basename,
            "timestamp": datetime.datetime.now().isoformat(),
            "active_flags": cfg.get("active_flags", []),
            "flags_mask": cfg.get("flags_mask", "0x0"),
        }
    }

    # Merge header with cfg for output
    output = {**header, **cfg}

    match chose.lower():
        case "json":
            path = file_path.with_suffix(".json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(output, f, indent=2)  # pretty JSON dump
        case "yaml":
            path = file_path.with_suffix(".yml")
            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(output, f, default_flow_style=False)
        case _:
            print(f"{chose} is an invalid choice!")
    return file_path

def main():
    choice = "yaml" if len(sys.argv) < 2 else sys.argv[1].lower()
    cfg = load_yaml_file()
    pth = write_dat_file(cfg, choice)
    print(f"print Data File Written to {pth}")

if __name__ == "__main__":
    main()

"""
Package: BotScanner
Author: Leon McClatchey
Company: Linktech Engineering LLC
Created: 2026-01-19
Modified: 2026-02-16
File: BotScanner/firewall/enforcers/nftables/nftables.py
Description: Describe the purpose of this file
"""
# System Libraries
from typing import Optional
from pathlib import Path
# Project Libraries
from BotScanner.net.discovery import NetDiscovery
from BotScanner.net import sudo_run
from ...baseline import BaseLine
from ...backend.nftables import NftablesBackend
from ...rule import Rule

class NftablesEnforcer:
    def __init__(self, cfg, lgr_cfg):    
        self.cfg = cfg
        self.lgr_cfg = lgr_cfg

        factory = lgr_cfg.get("factory")
        self.logger = factory.get_logger("nftables") if factory else None

        self.backend = NftablesBackend(cfg=cfg, lgr_cfg=lgr_cfg)
        self.baseline_store = BaseLine(cfg=cfg, lgr_cfg=lgr_cfg)
 
    def list_tables(self):
        return self.backend.list_tables()

    def parse_kernel_rules(self):
        return self.backend.parse_ruleset()

    def enforce_canonical(self, tables, sets, chains, rules):
        return self.backend.apply_canonical(tables, sets, chains, rules)

    def save_kernel_baseline(self, rules):
        self.baseline_store.save_backend_baseline("kernel", "nftables", rules)

    def load_kernel_baseline(self):
        return self.baseline_store.load_backend_baseline("kernel", "nftables")

    def write_nxt(self, rules, path):
        self.backend.write_nft_file(rules, path)

    def load_nxt_into_kernel(self, path):
        self.backend.load_nft_file(path)

    def update_botblock_elements(self, elements):
        self.backend.sync_set_elements("botblock", elements)
    
    def create_set(self, table_name: str, pset: dict):
        return self.backend.create_set(table_name, pset)
     
    def delete_set(self, table_name, set_name):
        return self.backend.delete_set(table_name, set_name)

    def get_set_elements(self, table_name, set_name):
        return self.backend.get_set_elements(table_name, set_name)

    def add_set_elements(self, table_name, set_name, elements):
        return self.backend.add_set_elements(table_name, set_name, elements)

    def del_set_elements(self, table_name, set_name, elements):
        return self.backend.del_set_elements(table_name, set_name, elements)

    def extract_chains(self, table_name):
        return self.backend.extract_chains(table_name)

    def create_chain(self, table_name, chain_name, meta):
        return self.backend.create_chain(table_name, chain_name, meta)

    def delete_chain(self, table_name, chain_name):
        return self.backend.delete_chain(table_name, chain_name)

    def flush_chain(self, table_name, chain_name):
        return self.backend.flush_chain(table_name, chain_name)

    def parse_rules(self):
        return self.backend.parse_rules()  

    def load_nft(self):
        return self.backend.load_nft()


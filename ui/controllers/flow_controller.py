from typing import Any


class FlowController:
    def __init__(self):
        self.flows: list[dict[str, Any]] = []
        self.loaded_flows: list[dict[str, Any]] = []
        self.page_size: int = 2000

    # ---------- dataset ----------
    def set_flows(self, flows: list[dict[str, Any]]):
        self.flows = flows or []
        self.loaded_flows = self.flows[: self.page_size]

    def get_loaded(self):
        return self.loaded_flows
    
    def get_all(self):
        return self.flows

    def get_total_count(self):
        return len(self.flows)

    def get_loaded_count(self):
        return len(self.loaded_flows)    

    # ---------- paging ----------
    def load_next_page(self):
        start = len(self.loaded_flows)
        end = min(len(self.flows), start + self.page_size)

        if start >= end:
            return self.loaded_flows

        self.loaded_flows = self.flows[:end]
        return self.loaded_flows

    # ---------- conversation helper ----------
    def ensure_pair_loaded(self, src: str, dst: str):
        if not self.flows:
            return self.loaded_flows

        # već učitano?
        for f in self.loaded_flows:
            if not isinstance(f, dict):
                continue
            s = str(f.get("src_ip") or "")
            d = str(f.get("dst_ip") or "")
            if (s == src and d == dst) or (s == dst and d == src):
                return self.loaded_flows

        # nađi u full datasetu
        hit_idx = -1
        for i, f in enumerate(self.flows):
            if not isinstance(f, dict):
                continue
            s = str(f.get("src_ip") or "")
            d = str(f.get("dst_ip") or "")
            if (s == src and d == dst) or (s == dst and d == src):
                hit_idx = i
                break

        if hit_idx < 0:
            return self.loaded_flows

        end = min(len(self.flows), max(hit_idx + 1, len(self.loaded_flows)) + self.page_size)
        self.loaded_flows = self.flows[:end]

        return self.loaded_flows
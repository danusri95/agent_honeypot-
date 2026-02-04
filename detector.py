import os
import re
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput
from models import DetectionResult, Issue
from typing import List

UNISWAP_FACTORY_ADDRESSES = {
    # Mainnet Uniswap V2 factory
    1: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
    # Add other networks if needed
}

ZERO_ADDR = "0x0000000000000000000000000000000000000000"


class TokenDetector:
    def __init__(self, provider_url: str = None, network_id: int = 1):
        self.provider_url = provider_url or os.getenv("WEB3_PROVIDER_URL")
        self.network_id = network_id
        self.w3 = None
        if self.provider_url:
            self.w3 = Web3(Web3.HTTPProvider(self.provider_url))
        self.provider_available = bool(self.w3 and self.w3.isConnected())

    def _normalize_addr(self, addr: str) -> str:
        if not Web3.isAddress(addr):
            raise ValueError(f"Invalid address: {addr}")
        return Web3.toChecksumAddress(addr)

    def _get_code(self, addr: str) -> bytes:
        return self.w3.eth.get_code(addr)

    def _call_constant(self, contract, func_name: str):
        try:
            fn = getattr(contract.functions, func_name)
            return fn().call()
        except (BadFunctionCallOutput, AttributeError):
            return None

    def analyze_token(self, token_address: str) -> DetectionResult:
        if not self.provider_available:
            raise RuntimeError("Web3 provider is not available or not connected.")
        token = self._normalize_addr(token_address)
        code = self._get_code(token)
        if not code or code == b"":
            raise ValueError("No contract code found at that address.")

        issues: List[Issue] = []

        # Heuristic 1: Very small bytecode (proxy or minimal) -> suspicious if too small
        code_size = len(code)
        if code_size < 300:
            issues.append(Issue(code="SMALL_CODE", message=f"Contract bytecode is small ({code_size} bytes) — could be proxy/minimal/suspicious."))

        # Heuristic 2: Look for common honeypot/scam keywords in bytecode (strings)
        code_hex = code.hex()
        suspicious_patterns = {
            "blacklist": ["blacklist", "isBlacklisted", "blacklisted"],
            "tax": ["_tax", "taxFee", "feeOnTransfer", "liquidityFee", "reflection"],
            "mint": ["mint(address", "mintTo", "increaseSupply", "minting"],
            "burnFrom": ["burnFrom"],
            "onlyOwner": ["onlyOwner", "owner()"],
        }
        for key, terms in suspicious_patterns.items():
            for t in terms:
                if t.lower() in code_hex.lower() or t in str(code):
                    issues.append(Issue(code=f"PATTERN_{key.upper()}", message=f"Bytecode contains pattern/term '{t}' indicating {key} functionality."))

        # Heuristic 3: Check ownership (if Ownable present)
        # Try standard owner() function
        try:
            erc20_abi_partial = [
                {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
                {"constant": True, "inputs": [{"name": "owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"},
            ]
            contract = self.w3.eth.contract(address=token, abi=erc20_abi_partial)
            name = self._call_constant(contract, "name") or ""
            symbol = self._call_constant(contract, "symbol") or ""
            decimals = self._call_constant(contract, "decimals")
            total_supply = self._call_constant(contract, "totalSupply")
            owner = self._call_constant(contract, "owner")
            if owner and owner != ZERO_ADDR:
                issues.append(Issue(code="HAS_OWNER", message=f"Contract reports owner {owner}. Owner-controlled tokens can be risky."))
            elif owner == ZERO_ADDR:
                issues.append(Issue(code="RENOUNCED", message="Contract reports 0x0 owner (ownership renounced)."))
        except Exception:
            name = symbol = ""
            decimals = None
            total_supply = None
            owner = None

        # Heuristic 4: Liquidity check (Uniswap-like factory)
        factory_addr = UNISWAP_FACTORY_ADDRESSES.get(self.network_id)
        if factory_addr:
            try:
                factory_abi = [
                    {"constant": True, "inputs": [{"name": "tokenA", "type": "address"}, {"name": "tokenB", "type": "address"}], "name": "getPair", "outputs": [{"name": "pair", "type": "address"}], "type": "function"}
                ]
                # We will check token-WETH pair existence by checking getPair(token, WETH)
                # Common WETH address on mainnet:
                WETH_ADDR = Web3.toChecksumAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                factory = self.w3.eth.contract(address=factory_addr, abi=factory_abi)
                pair = factory.functions.getPair(token, WETH_ADDR).call()
                if pair == ZERO_ADDR or pair is None:
                    issues.append(Issue(code="NO_WETH_PAIR", message="No WETH pair found on Uniswap factory — liquidity may be absent or on another DEX."))
                else:
                    # Get reserves by calling pair contract's getReserves
                    pair_abi = [
                        {"constant": True, "inputs": [], "name": "getReserves", "outputs": [{"name": "_reserve0", "type": "uint112"}, {"name": "_reserve1", "type": "uint112"}, {"name": "_blockTimestampLast", "type": "uint32"}], "type": "function"},
                        {"constant": True, "inputs": [], "name": "token0", "outputs": [{"name": "", "type": "address"}], "type": "function"},
                        {"constant": True, "inputs": [], "name": "token1", "outputs": [{"name": "", "type": "address"}], "type": "function"},
                    ]
                    pair_contract = self.w3.eth.contract(address=pair, abi=pair_abi)
                    r = pair_contract.functions.getReserves().call()
                    reserve0, reserve1 = r[0], r[1]
                    if reserve0 == 0 and reserve1 == 0:
                        issues.append(Issue(code="ZERO_RESERVES", message="Pair exists but reserves are zero — liquidity likely removed."))
            except Exception:
                # ignore factory failures, not conclusive
                pass

        # Heuristic 5: High-level honeypot heuristic (cannot be definitive without tx simulation)
        # If code contains 'transfer' but also contains terms that suggest fee on transfer and blacklist, raise higher severity.
        if any(i.code.startswith("PATTERN_TAX") for i in issues) and any(i.code.startswith("PATTERN_BLACKLIST") for i in issues):
            issues.append(Issue(code="LIKELY_HONEYPOT", message="Bytecode patterns indicate a combination of transfer fees and blacklist/owner controls — possible honeypot."))

        score = max(0, min(100, 10 * len(issues)))  # simple scoring: 10 points per issue (cap 100)

        details = {
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "total_supply": str(total_supply) if total_supply is not None else None,
            "owner": owner
        }

        return DetectionResult(address=token, score=score, issues=issues, details=details)
[README.md](https://github.com/user-attachments/files/25065355/README.md)
# Honeypot & Scam Detection Agent (Starter)

This is a starter implementation of a honeypot/scam detection agent for Ethereum ERC-20 tokens with a simple HTTP API.

Features
- Heuristic checks on contract bytecode
- Basic on-chain checks (owner, supply, liquidity pair/reserves)
- Simple scoring and list of detected issues
- FastAPI-based HTTP API

Requirements
- Python 3.9+
- An Ethereum node provider URL (Infura / Alchemy / other) set in environment variable `WEB3_PROVIDER_URL`

Quick start
1. Copy `.env.example` to `.env` and set `WEB3_PROVIDER_URL`.
2. Install dependencies:
   pip install -r requirements.txt
3. Run the API:
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
4. Call the detector:
   GET /detect?token_address=0x...  

Notes & next steps
- This implementation uses heuristic static analysis and a few on-chain queries. It is not definitive.
- To improve detection:
  - Fetch and parse full contract ABI (Etherscan) and scan function signatures.
  - Simulate a buy/sell in a forked node or use a mempool simulation to detect sell-blocking honeypots.
  - Detect tax percentages by parsing functions or monitoring transfer events.
  - Cross-reference token with known scam lists.
  - Add caching, rate limiting, batch endpoints, authentication, and background workers.
- If you want a Node.js/TypeScript implementation or support for other chains (BSC, Polygon, etc.) I can provide that.

Security & disclaimers
- Use this tool for research and triage only. It may produce false positives/negatives.
- Do not rely solely on automated checks for investment decisions.

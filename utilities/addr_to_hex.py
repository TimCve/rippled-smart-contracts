import sys
from xrpl.core.addresscodec import decode_classic_address, ensure_classic_address

addr = sys.argv[1]

classic = ensure_classic_address(addr)
account_id_bytes = decode_classic_address(classic)

print(account_id_bytes.hex())  # 40 hex chars

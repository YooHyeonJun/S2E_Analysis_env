import re
import sys

def parse_log(filename):
    gates = {}
    with open(filename, 'r') as f:
        for line in f:
            if 'api=parser_gate' in line:
                m_gate = re.search(r'gate=(0x[0-9a-f]+)', line)
                m_taken = re.search(r'taken=([01])', line)
                m_ecx = re.search(r'\secx=(0x[0-9a-f]+)', line)
                m_eax = re.search(r'\seax=(0x[0-9a-f]+)', line)
                m_ctx = re.search(r'\sctx=(0x[0-9a-f]+|na)', line)
                
                if m_gate and m_taken:
                    gate = m_gate.group(1)
                    if gate not in gates:
                        gates[gate] = []
                    
                    entry = {
                        "taken": m_taken.group(1),
                        "ecx": m_ecx.group(1) if m_ecx else "na",
                        "eax": m_eax.group(1) if m_eax else "na",
                        "ctx": m_ctx.group(1) if m_ctx else "na"
                    }
                    if entry not in gates[gate]:
                        gates[gate].append(entry)

    print("=== 게이트별 관측된 상태 (유니크) ===")
    for gate in sorted(gates.keys()):
        print(f"Gate {gate}:")
        for st in gates[gate]:
            print(f"  - taken={st['taken']} | ecx={st['ecx']} | eax={st['eax']} | ctx={st['ctx']}")

parse_log("logs/profiles/rat_staged/20260331_111900.log")

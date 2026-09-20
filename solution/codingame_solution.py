"""
CodinGame - "Encryption/Decryption of Enigma Machine" (Easy)
https://www.codingame.com/training/easy/encryptiondecryption-of-enigma-machine

Self-contained solution, submitted as-is (validator score: 100%).
This file is kept ASCII-only and byte-identical to the accepted submission;
the Ukrainian write-up lives in README.md and in src/enigma/.

Input format:
    line 1   : ENCODE | DECODE
    line 2   : starting shift N
    lines 3-5: three rotors (26 uppercase letters each)
    line 6   : the message

Encryption:
    c[i] = S[ (m[i] + N + i) mod 26 ],   S = R3 . R2 . R1
Decryption (exact inverse):
    m[i] = ( S^-1[c[i]] - N - i ) mod 26

The three rotors are composed into a single substitution S *before* the
message loop, because a composition of bijections is again a bijection.
That leaves exactly one table lookup per character:
time O(L + 26k), extra memory O(26).
"""

import sys

A = ord("A")
M = 26


def main() -> None:
    data = sys.stdin.read().split()
    mode = data[0].upper()
    shift = int(data[1]) % M
    rotors = data[2:5]
    message = data[5] if len(data) > 5 else ""

    # Collapse the rotor cascade into one substitution table.
    s = list(range(M))
    for wiring in rotors:
        table = [ord(ch) - A for ch in wiring]
        s = [table[x] for x in s]

    if mode == "ENCODE":
        out = [
            chr(A + s[(ord(ch) - A + shift + i) % M])
            for i, ch in enumerate(message)
        ]
    else:
        inv = [0] * M
        for i, v in enumerate(s):
            inv[v] = i
        out = [
            chr(A + (inv[ord(ch) - A] - shift - i) % M)
            for i, ch in enumerate(message)
        ]

    print("".join(out))


if __name__ == "__main__":
    main()

## Perfect secrecy

A cipher has **perfect secrecy** if the ciphertext reveals nothing about the message.

For all messages $m_0, m_1$ of the same length and every ciphertext $c$:

$$
P[E(k, m_0) = c] = P[E(k, m_1) = c]
$$

where the key $k$ is chosen uniformly at random.

Intuition: given a ciphertext $c$, every message $m_1, m_2, \dots$ is equally likely to be the one that was encrypted.

---

## One-time pad (OTP)

Encryption and decryption are both XOR with the key:

$$
c = m \oplus k \qquad\qquad m = c \oplus k
$$

**Properties**

- With a truly random key, OTP has **perfect secrecy**.
- The key must be **at least as long as the message**.
- The key must be agreed on **before** communication.
- The key must **never be reused**.

→ Secure, but **impractical**.

---

## Pseudorandom generator (PRG)

**Idea:** replace the truly random key with a *pseudorandom* one, expanded from a short random seed.

$$
G: \{0,1\}^s \to \{0,1\}^n, \quad s < n
$$

Using $c = m \oplus G(k)$ gives a **stream cipher**.

A stream cipher is **not perfectly secure**, since the key is shorter than the message (Shannon: perfect secrecy requires $|K| \ge |M|$).

### Example

$G: \{0,1\}^2 \to \{0,1\}^3$

| seed | $G(\text{seed})$ |
|------|------------------|
| 00   | 000              |
| 01   | 100              |
| 10   | 111              |
| 11   | 001              |

$$
P[G(k) = 000] = \tfrac{1}{4} \qquad \text{vs.} \qquad P[\text{truly random} = 000] = \tfrac{1}{8}
$$

→ The distributions differ: $G$ hits only 4 of the 8 possible outputs, so its output can be distinguished from truly random.

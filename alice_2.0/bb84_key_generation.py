import random

def generate_qubits(n):
    """
    Simulates Alice generating qubits and encoding them in random bases.
    """
    # Generate random bits (0 or 1) and random bases (0: rectilinear, 1: diagonal)
    bits = [random.randint(0, 1) for _ in range(n)]
    bases = [random.randint(0, 1) for _ in range(n)]
    return bits, bases

def measure_qubits(bits, alice_bases, bob_bases):
    """
    Simulates Bob measuring the qubits sent by Alice.
    """
    # Bob's measurements depend on whether his basis matches Alice's
    measurements = []
    for i in range(len(bits)):
        if alice_bases[i] == bob_bases[i]:
            measurements.append(bits[i])  # Correct measurement
        else:
            measurements.append(random.randint(0, 1))  # Random measurement
    return measurements

def reconcile_bases(alice_bases, bob_bases, alice_bits, bob_bits):
    """
    Alice and Bob compare their bases and keep only the bits where their bases match.
    """
    key = []
    for i in range(len(alice_bases)):
        if alice_bases[i] == bob_bases[i]:
            key.append(alice_bits[i])  # Both have the same bit due to matching bases
    return key

def detect_eavesdropping(key_sample, alice_sample, bob_sample):
    """
    Compares a random sample of the key to detect eavesdropping.
    """
    errors = sum(1 for a, b in zip(alice_sample, bob_sample) if a != b)
    error_rate = errors / len(key_sample)
    return error_rate

def generate_bb84_key(n=100):
    """
    Simulates the entire BB84 protocol to generate a shared secret key.
    """
    # Step 1: Alice generates random bits and bases
    alice_bits, alice_bases = generate_qubits(n)

    # Step 2: Bob randomly chooses bases to measure the qubits
    bob_bases = [random.randint(0, 1) for _ in range(n)]
    bob_bits = measure_qubits(alice_bits, alice_bases, bob_bases)

    # Step 3: Alice and Bob reconcile their bases
    shared_key = reconcile_bases(alice_bases, bob_bases, alice_bits, bob_bits)

    # Step 4: Detect eavesdropping (optional in simulation)
    if len(shared_key) > 10:  # Ensure enough bits for sampling
        sample_size = len(shared_key) // 5
        key_sample = random.sample(range(len(shared_key)), sample_size)
        alice_sample = [shared_key[i] for i in key_sample]
        bob_sample = [shared_key[i] for i in key_sample]
        error_rate = detect_eavesdropping(key_sample, alice_sample, bob_sample)
        if error_rate > 0.05:  # Threshold for eavesdropping detection
            raise SecurityError(f"Eavesdropping detected! Error rate: {error_rate:.2%}")

    return shared_key

# Custom Exception
class SecurityError(Exception):
    pass

if __name__ == "__main__":
    try:
        print("Generating BB84 shared key...")
        bb84_key = generate_bb84_key(100)
        print("Generated BB84 Key:", bb84_key)
        print("Key Length:", len(bb84_key))
    except SecurityError as e:
        print(e)

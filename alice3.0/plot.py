import time
import numpy as np
import matplotlib.pyplot as plt
from hybrid_crypto import hybrid_encrypt, hybrid_decrypt

# Simulated BB84 shared key for encryption/decryption
def generate_shared_key(length=128):
    return np.random.randint(0, 2, size=length).tolist()

# Initialize lists to store results
data_sizes = [10, 50, 100, 500, 1000,2000,3000,4000, 5000]  # Data sizes in KB
encryption_times = []
decryption_times = []
encryption_throughputs = []
decryption_throughputs = []
storage_efficiencies = []

# Iterate through different data sizes
for size in data_sizes:
    # Generate random data of specified size in KB
    data = np.random.bytes(size * 1024)  # Size in bytes
    data_size_kb = len(data) / 1024  # Confirm data size in KB
    
    # Generate a simulated shared key
    key = generate_shared_key()

    # Measure Encryption Time
    start_time = time.perf_counter()
    encrypted_data = hybrid_encrypt(data, key)
    encryption_time = time.perf_counter() - start_time
    encryption_times.append(encryption_time)

    # Measure Encryption Throughput
    encryption_throughput = data_size_kb / encryption_time if encryption_time > 0 else float('inf')
    encryption_throughputs.append(encryption_throughput)

    # Measure Decryption Time
    start_time = time.perf_counter()
    decrypted_data = hybrid_decrypt(encrypted_data, key)
    decryption_time = time.perf_counter() - start_time
    decryption_times.append(decryption_time)

    # Measure Decryption Throughput
    decryption_throughput = data_size_kb / decryption_time if decryption_time > 0 else float('inf')
    decryption_throughputs.append(decryption_throughput)

    # Measure Storage Efficiency
    encrypted_data_size_kb = len(encrypted_data) / 1024  # Encrypted data size in KB
    storage_efficiency = data_size_kb / encrypted_data_size_kb if encrypted_data_size_kb > 0 else 0
    storage_efficiencies.append(storage_efficiency)

    # Validate Decrypted Data
    assert decrypted_data == data, "Decryption failed! Decrypted data does not match original."

# Plot Metrics
# Plot 1: Data Size vs Encryption/Decryption Time
plt.figure(figsize=(10, 6))
plt.plot(data_sizes, encryption_times, marker='o', label='Encryption Time (s)')
plt.plot(data_sizes, decryption_times, marker='s', label='Decryption Time (s)')
plt.xlabel('Data Size (KB)')
plt.ylabel('Time (s)')
plt.title('Data Size vs Encryption/Decryption Time')
plt.legend()
plt.grid(True)
plt.show()

# Plot 2: Data Size vs Encryption/Decryption Throughput
plt.figure(figsize=(10, 6))
plt.plot(data_sizes, encryption_throughputs, marker='o', label='Encryption Throughput (KB/s)')
plt.plot(data_sizes, decryption_throughputs, marker='s', label='Decryption Throughput (KB/s)')
plt.xlabel('Data Size (KB)')
plt.ylabel('Throughput (KB/s)')
plt.title('Data Size vs Encryption/Decryption Throughput')
plt.legend()
plt.grid(True)
plt.show()

# Plot 3: Data Size vs Storage Efficiency
plt.figure(figsize=(10, 6))
plt.plot(data_sizes, storage_efficiencies, marker='o', color='g', label='Storage Efficiency')
plt.xlabel('Data Size (KB)')
plt.ylabel('Storage Efficiency (Original/Encrypted)')
plt.title('Data Size vs Storage Efficiency')
plt.legend()
plt.grid(True)
plt.show()

# Print Metrics Summary
print("=== Metrics Summary ===")
print(f"{'Data Size (KB)':<15} {'Enc Time (s)':<15} {'Dec Time (s)':<15} {'Enc Throughput (KB/s)':<25} {'Dec Throughput (KB/s)':<25} {'Storage Efficiency':<20}")
for i in range(len(data_sizes)):
    print(f"{data_sizes[i]:<15} {encryption_times[i]:<15.5f} {decryption_times[i]:<15.5f} {encryption_throughputs[i]:<25.5f} {decryption_throughputs[i]:<25.5f} {storage_efficiencies[i]:<20.5f}")

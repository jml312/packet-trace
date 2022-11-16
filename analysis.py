# %%
import os
from matplotlib import pyplot as plt

# %%
file_name = os.getcwd() + "/l.txt"
length_data = []
with open(file_name, 'r') as f:
    lines = f.readlines()
    lines = [line.strip() for line in lines]
    for line in lines:
        ts, caplen, ip_len, iphl, transport, trans_hl, payload_len = line.split()
        length_data.append([int(ip_len), transport])

# %%
def plot_hist(transport_type, xlabel):
    plt.hist([ip_len for ip_len,
             transport in length_data if transport == transport_type], bins=20)
    plt.xlabel(xlabel)
    plt.ylabel("Frequency")


# %%
plt.suptitle("IPV4 Packet Lengths by Transport Protocol")

plt.subplot(3, 1, 1)
plot_hist('T', 'TCP (Bytes)')

plt.subplot(3, 1, 2)
plot_hist('U', 'UDP (Bytes)')

plt.subplot(3, 1, 3)
plot_hist('?', 'Unknown (Bytes)')

plt.subplots_adjust(hspace=0.85)
plt.show()

# %%
for transport_type in ['T', 'U', '?']:
    data = [ip_len for ip_len,
            transport in length_data if transport == transport_type]
    print("Mean for transport type {}: {}".format(
        transport_type, round(sum(data) / len(data), 2)))

"""
Hard-coded graph generation for figure showing cookie support across alexa, tld, rrs
"""

import matplotlib.pyplot as plt
import numpy as np

plt.figure(figsize=(4.8, 0.8))
plt.rc('font', size=8)

y_ticks = np.arange(3)
# numbers from jlp
alexa = [x / (157679 - 6724) * 100 for x in [43737, 48262, 147878]]
tld = [x / (6615 - 58) * 100 for x in [1249, 1249, 6557]]
rrs = [x / 999228 * 100 for x in [167402, 208526, 699402]]

server = [rrs[0], alexa[0], tld[0]]
client = [rrs[1] - rrs[0], alexa[1] - alexa[0], tld[1] - tld[0]]
edns = [rrs[2] - rrs[1], alexa[2] - alexa[1], tld[2] - tld[1]]

p_server = plt.barh(y_ticks, server)
p_client = plt.barh(y_ticks, client, left=server)
p_edns = plt.barh(y_ticks, edns, left=[rrs[1], alexa[1], tld[1]])

plt.yticks(y_ticks, ('RRs', 'Alexa', 'TLDs'))
plt.xticks(np.arange(0, 101, 10), [f'{x}%' for x in np.arange(0, 101, 10)])
plt.legend((p_server[0], p_client[0], p_edns), ('Sent Server Cookie', 'Echoed Client Cookie', "Sent EDNS"),
           bbox_to_anchor=(-.1, 1.02, 1.2, .102), loc='lower left',
           ncol=3, mode="expand", borderaxespad=0.)

plt.savefig('support.pdf', bbox_inches='tight', pad_inches=0)

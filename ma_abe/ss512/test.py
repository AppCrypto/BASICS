import numpy as np
import tk
import matplotlib as mpl
mpl.use("TKAgg") # Use TKAgg to show figures

import matplotlib.pyplot as plt

x = [1,2,3] # 50 x-axis points
y = [1,2,3] # y = sin(x)
plt.plot(x, y)
plt.show()
plt.savefig("temp.png") # save figure

sudo -H python3 -m pip install setting

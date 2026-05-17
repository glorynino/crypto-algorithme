import numpy as np
import matplotlib.pyplot as plt

f = np.linspace(-5, 5, 1000)
P_f = 2 * np.sinc(2 * f)

plt.figure(figsize=(8, 4))
plt.plot(f, np.abs(P_f), color='dodgerblue')
plt.title(r"$|P(f)|_{\,\omega=2\pi f}$")
plt.xlabel("Fréquence en (Hz)")
plt.ylabel("Amplitude")
plt.grid(True)
plt.show()
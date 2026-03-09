import json
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde

# Carregar os resultados pre-calculados pelo Go interno (Vexil)
# Este JSON foi extraído diretamente de shannonEntropy() sobre os exemplos 
# textuais da vida real no diretório testdata/corpus/
with open('testdata/empirical_entropy.json', 'r') as f:
    data = json.load(f)

p_data = np.array(data['placeholders'])
s_data = np.array(data['secrets'])

plt.figure(figsize=(11, 6), dpi=300)

# KDE (Kernel Density Estimation) para uma curva suave empírica
kde_p = gaussian_kde(p_data, bw_method=0.4)
kde_s = gaussian_kde(s_data, bw_method=0.4)

x_p = np.linspace(0, 4.5, 500)
x_s = np.linspace(3.0, 6.5, 500)

plt.plot(x_p, kde_p(x_p), color='#e63946', linewidth=2.5)
plt.fill_between(x_p, kde_p(x_p), alpha=0.6, color='#e63946', 
                 label='Domínio Humano Empírico (Placeholders)')

plt.plot(x_s, kde_s(x_s), color='#457b9d', linewidth=2.5)
plt.fill_between(x_s, kde_s(x_s), alpha=0.6, color='#457b9d', 
                 label='Domínio CSPRNG Empírico (Tokens/Secrets)')

# Valores médios observados
p_mean = np.mean(p_data)
s_mean = np.mean(s_data)

plt.axvline(x=p_mean, color='#8f1a23', linestyle=':', linewidth=1.5)
plt.axvline(x=s_mean, color='#1e3d54', linestyle=':', linewidth=1.5)

# Hyperplano Vexil
plt.axvline(x=3.5, color='#1d3557', linestyle='--', linewidth=2.5, 
            label='Hiperplano Vexil (Threshold θ = 3.5 bits/char)')

# Rejeições Falsos Positivos e Tolerância
plt.text(p_mean, plt.ylim()[1] * 0.4, f'E[H] Observado:\n{p_mean:.2f} bits/char', 
         fontsize=10, color='#8f1a23', ha='center', va='center',
         bbox=dict(facecolor='white', alpha=0.8, edgecolor='none'))

plt.text(s_mean, plt.ylim()[1] * 0.4, f'E[H] Observado:\n{s_mean:.2f} bits/char', 
         fontsize=10, color='#1e3d54', ha='center', va='center',
         bbox=dict(facecolor='white', alpha=0.8, edgecolor='none'))

# Estilização
plt.title('Distribuição Empírica de Entropia de Shannon (Vexil testdata)', 
          fontsize=14, fontweight='bold', pad=15)
plt.xlabel('Entropia de Shannon (bits/char)', fontsize=12, fontweight='bold')
plt.ylabel('Densidade Observada (KDE)', fontsize=12, fontweight='bold')

plt.xlim(0, 6.5)
plt.ylim(bottom=0)
plt.legend(loc='upper right', frameon=True, shadow=True, fontsize=10)
plt.grid(axis='y', alpha=0.3, linestyle='--')

ax = plt.gca()
ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)

plt.tight_layout()

output_file = 'shannon_entropy_empirical_graph.png'
plt.savefig(output_file, format='png', bbox_inches='tight')
print(f"Gráfico empírico salvo com sucesso em: {output_file}")

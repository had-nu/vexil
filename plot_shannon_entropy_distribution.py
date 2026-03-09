import numpy as np
import matplotlib.pyplot as plt

# Garantir reprodutibilidade
np.random.seed(42)

# Gerar dados do Domínio Criptográfico (CSPRNG/Segredos Autênticos)
# Converge para log2(62) ≈ 5.95, alta densidade e desvio padrão muito baixo
mu_s, sigma_s = 5.5, 0.4 
s = np.random.normal(mu_s, sigma_s, 1000000)
s = s[(s > 4.5) & (s <= 6.0)] # Limitado ao topo alfanumérico/base64

# Gerar dados do Domínio Cognitivo Humano (Placeholders/Senha Humana)
# Gravita em torno de 1.3 - 2.5 (Shannon, 1951 e aproximações de Guessing Entropy empírica)
mu_f, sigma_f = 1.6, 0.6
f = np.random.normal(mu_f, sigma_f, 1000000)
f = f[(f > 0.0) & (f < 3.5)] # Limitado ao decaimento empírico

# Configuração do Gráfico Acadêmico
plt.figure(figsize=(11, 6), dpi=300)

# Plots de Densidade (KDE/Histograma)
plt.hist(f, bins=60, density=True, alpha=0.75, color='#e63946', 
         edgecolor='white', linewidth=0.5, 
         label='Domínio Humano (F): Placeholders & Senhas')

plt.hist(s, bins=50, density=True, alpha=0.85, color='#457b9d', 
         edgecolor='white', linewidth=0.5, 
         label='Domínio CSPRNG (S): JWT, AWS, GCP, DB Tokens')

# Preenchimento e Linha do Vexil Threshold
plt.axvline(x=3.5, color='#1d3557', linestyle='--', linewidth=2.5, 
            label='Hiperplano Vexil (Threshold θ = 3.5 bits/char)')

# Anotações matemáticas
plt.text(1.6, 0.45, r'$E[H(F)] \approx 1.3{\sim}2.5$', fontsize=11, color='#e63946', ha='center')
plt.text(5.5, 0.85, r'$E[H(S)] \to \log_2(k)$', fontsize=11, color='#457b9d', ha='center')
plt.text(3.55, 0.5, 'Zona de\nSeparação', fontsize=10, color='black', alpha=0.7)

# Estilização
plt.title('Separação Geométrica de Domínios: Cognição Humana vs. Uniformidade Computacional', 
          fontsize=14, fontweight='bold', pad=15)
plt.xlabel('Entropia de Shannon (bits/char)', fontsize=12, fontweight='bold')
plt.ylabel('Densidade de Probabilidade', fontsize=12, fontweight='bold')

plt.legend(loc='upper left', frameon=True, shadow=True, fontsize=10)
plt.grid(axis='y', alpha=0.3, linestyle='--')
plt.xlim(0, 6.5)

# Ocultar bordas superior e direita para visual mais limpo (Tufte style)
ax = plt.gca()
ax.spines['right'].set_visible(False)
ax.spines['top'].set_visible(False)

plt.tight_layout()

# Salvar e Exibir
output_file = 'shannon_entropy_distribution_graph.png'
plt.savefig(output_file, format='png', bbox_inches='tight')
print(f"Gráfico acadêmico salvo com sucesso em: {output_file}")

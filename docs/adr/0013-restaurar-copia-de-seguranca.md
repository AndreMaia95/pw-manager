# Restaurar uma cópia de segurança é uma operação explícita, não uma fusão

Como a fusão dá vitória à alteração mais recente (ADR-0003) e as lápides vencem entradas antigas, fundir uma cópia de segurança não teria efeito. Restaurar é por isso explícito: abrir a cópia só para leitura e restaurar entradas individuais (o caso habitual), ou restaurar o cofre inteiro; em ambos os casos o restaurado é gravado como edições novas, e no restauro total as entradas ausentes da cópia vão para o lixo. Cada cópia guarda o chaveiro do seu momento e abre com a palavra-passe mestra então em vigor.

# Cada réplica contém o estado completo do cofre; lápides para sempre

Cada réplica guarda o estado fundido completo que o seu dispositivo conhece, incluindo lápides, e não só as alterações desse dispositivo. Qualquer réplica chega para reconstruir o cofre, e retirar um dispositivo é só apagar a sua réplica. As lápides nunca são purgadas: são minúsculas, e purgá-las faria um dispositivo que esteve meses offline ressuscitar entradas apagadas. O histórico (últimas 10 versões) e o conteúdo de entradas apagadas são eliminados quando a entrada sai do lixo (30 dias).

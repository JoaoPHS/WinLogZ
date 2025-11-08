# config.py - Configurações de filtro para falsos positivos

FILTER_CONFIG = {
    'trusted_ips': [
        '192.168.1.1',    # Gateway
        '192.168.1.100',  # Servidor interno
        '192.168.1.200',  # Outro servidor
    ],
    
    'trusted_users': [
        'SYSTEM',
        'LOCAL SERVICE', 
        'NETWORK SERVICE',
        'Administrador',
        'sqlservice'  # Service accounts
    ],
    
    'trusted_processes': [
        'svchost.exe',
        'msmpeng.exe',  # Windows Defender
        'winlogon.exe',
        'csrss.exe'
    ],
    
    # Event IDs que geralmente são ruído
    'noisy_events': [4624, 4634, 4648],
    
    'thresholds': {
        'failed_logins': 10,      # Tentativas antes de alertar
        'time_window': 30,        # Janela de tempo em minutos
        'business_hours': [8, 18] # Horário comercial
    }
}
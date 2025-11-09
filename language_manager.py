LANGUAGES = {
    'pt_BR': {
        # Interface principal
        'title': "WinLogZ - Windows Log Analyzer v1.0",
        'filter_checkbox': "[X] Filtrar falsos positivos",
        'filter_active': "FILTROS ATIVOS",
        'filter_disabled': "FILTROS DESATIVADOS",
        'analyze_button': "INICIAR ANÁLISE DE LOGS",
        'report_button': "GERAR RELATÓRIO",
        'clear_button': "LIMPAR CONSOLE",
        'status_ready': ">>> SISTEMA PRONTO <<<",
        'status_analyzing': ">>> ANALISANDO LOGS...",
        'status_complete': ">>> ANÁLISE CONCLUÍDA: {} AMEAÇAS DETECTADAS",
        'status_complete_clean': ">>> ANÁLISE CONCLUÍDA: SISTEMA LIMPO",
        'status_error': ">>> ERRO NO SISTEMA",

        'developed_by': "Desenvolvido por: João Pedro H. > Gitlab: @PHDevSec",

        
        # Mensagens de boas-vindas
        'welcome_title': ">>> WinLogZ - Windows Log Analyzer v1.0",
        'welcome_version': ">>> SISTEMA AVANÇADO DE ANÁLISE DE LOGS",
        'welcome_initializing': ">>> INICIALIZANDO MÓDULOS DE SEGURANÇA...",
        'welcome_access': "[PERMITIDO] ACESSO AOS LOGS DO SISTEMA",
        'welcome_privilege': "[ADMINISTRADOR] PRIVILÉGIOS ELEVADOS CONFIRMADOS",
        'welcome_commands': ">>> COMANDOS DISPONÍVEIS:",
        'welcome_analyze_desc': "  INICIAR ANÁLISE DE LOGS - Executar varredura completa de segurança",
        'welcome_report_desc': "  GERAR RELATÓRIO - Gerar relatório detalhado",
        'welcome_clear_desc': "  LIMPAR CONSOLE - Limpar console de resultados",
        
        
        # Mensagens de análise
        'analysis_starting': ">>> INICIANDO PROTOCOLO DE VARREdura DE SEGURANÇA",
        'config_filters_enabled': "[CONFIG] Filtros de falsos positivos: ATIVADOS",
        'config_system_events': "[CONFIG] Monitorando eventos do sistema...",
        'config_filters_disabled': "[CONFIG] Filtros de falsos positivos: DESATIVADOS",
        'config_showing_all': "[CONFIG] Mostrando todos os eventos...",
        
        # Resultados
        'results_summary': ">>> RESUMO DOS RESULTADOS",
        'results_mode_active': "[MODO] Filtros de falsos positivos: ATIVO",
        'results_mode_inactive': "[MODO] Filtros de falsos positivos: INATIVO",
        'results_total': "[TOTAL] {} atividades detectadas",
        'results_high': "[ALTO] {} ameaças de alta severidade",
        'results_medium': "[MÉDIO] {} ameaças de média severidade", 
        'results_low': "[BAIXO] {} ameaças de baixa severidade",
        'results_threat_details': ">>> DETALHES DAS AMEAÇAS",
        'results_threat': "--- AMEAÇA {} [{}] ---",
        'results_type': "[TIPO] {}",
        'results_eventid': "[EVENTO] {}",
        'results_time': "[HORÁRIO] {}",
        'results_description': "[DESCRIÇÃO] {}",
        'results_details': "[DETALHES]",
        'results_clean': "✅ Nenhuma ameaça crítica detectada",
        'results_no_threats': "📊 Sistema operando dentro dos parâmetros normais",
        'results_filters_working': "🛡️ Filtros preveniram falsos positivos",
        'results_secure': "🔒 Sistema considerado seguro",
        'results_complete': ">>> VARREdura DE SEGURANÇA CONCLUÍDA",
        'results_ready': "Pronto para o próximo comando...",
        
        # Erros
        'error_system': "❌ ERRO NO SISTEMA",
        'error_message': "💡 Detalhes: {}",
        'error_permissions': "🔒 Verifique as permissões de administrador",
        'error_admin_required': "❌ Execução sem privilégios de administrador",
        'error_admin_suggestion': "💡 Execute como administrador para acesso completo",
        
        # Relatórios
        'report_generated': "📄 RELATÓRIO GERADO COM SUCESSO",
        'report_file': "📁 Arquivo: {}",
        'report_location': "📂 Localização: {}",
        'report_saved': "Relatório Salvo",
        
        # Console
        'console_cleared': ">>> CONSOLE LIMPO",
        'console_ready': ">>> SISTEMA PRONTO",
        'console_continue': ">>> AGUARDANDO COMANDOS...",
        
        # Log Analyzer - Análise com filtros
        'log_analyzer_connecting': "🔍 Conectando ao serviço de logs do Windows...",
        'log_analyzer_reading_events': "📂 Lendo eventos de segurança...",
        'log_analyzer_processing_batch': "📦 Processando lote {} ({} eventos)...",
        'log_analyzer_collection_complete': "✅ Coleta concluída: {} eventos coletados",
        'log_analyzer_access_error': "❌ Erro ao acessar logs: {}",
        'log_analyzer_analyzing_failed_logins': "\n🔐 Analisando tentativas de login falhas...",
        'log_analyzer_failures_statistics': "   📊 Estatísticas: {} falhas totais, {} filtradas",
        'log_analyzer_failures_statistics_no_filters': "   📊 Estatísticas: {} falhas totais (filtros desativados)",
        'log_analyzer_checking_ips': "   🔎 Verificando {} IPs...",
        'log_analyzer_possible_brute_force': "   🚨 POSSÍVEL FORÇA BRUTA: IP {} - {} tentativas",
        'log_analyzer_trusted_ip_ignored': "   ✅ IP confiável ignorado: {}",
        'log_analyzer_normal_event': "   📍 Evento normal: IP {} - {} tentativas",
        'log_analyzer_analyzing_privilege_escalation': "\n🛡️ Analisando eventos de escalação de privilégios...",
        'log_analyzer_checking_eventid': "   🔍 Verificando EventID {}...",
        'log_analyzer_filtered_noise': "   ⚡ Evento {} filtrado (ruído comum)",
        'log_analyzer_filtered_system_user': "   ⚡ Evento {} filtrado (usuário sistema: {})",
        'log_analyzer_filtered_system_process': "   ⚡ Evento {} filtrado (processo sistema: {})",
        'log_analyzer_critical_event': "   🚨 EVENTO CRÍTICO: {}",
        'log_analyzer_suspicious_event': "   ⚠️  Evento detectado: {}",
        'log_analyzer_privilege_statistics': "   📊 Estatísticas: {} eventos, {} filtrados, {} suspeitos",
        'log_analyzer_privilege_statistics_no_filters': "   📊 Estatísticas: {} eventos detectados (filtros desativados)",
        'log_analyzer_starting_with_filters': "🚀 INICIANDO ANÁLISE COM FILTROS ATIVOS",
        'log_analyzer_filters_note': "💡 Falsos positivos serão automaticamente filtrados",
        'log_analyzer_starting_without_filters': "🚀 INICIANDO ANÁLISE COM FILTROS DESATIVADOS",
        'log_analyzer_no_filters_note': "💡 Mostrando TODOS os eventos detectados",
        'log_analyzer_no_events': "❌ Nenhum evento coletado. Verifique permissões.",
        'log_analyzer_analyzing_events': "\n📈 Analisando {} eventos coletados...",
        'log_analyzer_analysis_complete_with_filters': "✅ ANÁLISE CONCLUÍDA: {} atividades suspeitas após filtros",
        'log_analyzer_analysis_complete_without_filters': "✅ ANÁLISE CONCLUÍDA: {} atividades detectadas (filtros desativados)",
        'log_analyzer_brute_force_type': "Possível Ataque de Força Bruta",
        'log_analyzer_brute_force_details': 'IP: {}, Tentativas: {}',
        'log_analyzer_privilege_escalation_type': "Escalação de Privilégios",
        'log_analyzer_privilege_event_4672': "Atribuição de privilégios especiais",
        'log_analyzer_privilege_event_4728': "Membro adicionado ao grupo de delegação",
        'log_analyzer_privilege_event_4732': "Membro adicionado ao grupo de administradores locais",
        'log_analyzer_privilege_event_4735': "Grupo de segurança alterado",
        'log_analyzer_privilege_event_4670': "Permissões de objeto alteradas",
        
        # Log Analyzer - Análise detalhada sem filtros
        'log_analyzer_detailed_mode': "📋 MODO DETALHADO: Mostrando TODOS os eventos coletados",
        'log_analyzer_detailed_analysis': "🔍 INICIANDO ANÁLISE DETALHADA SEM FILTROS",
        'log_analyzer_general_stats': "📊 ESTATÍSTICAS GERAIS:",
        'log_analyzer_total_events': "   📈 Total de eventos coletados: {}",
        'log_analyzer_event_types': "   🏷️  Tipos de eventos diferentes: {}",
        'log_analyzer_failed_login_analysis': "🔐 ANÁLISE DETALHADA DE FALHAS DE LOGIN:",
        'log_analyzer_privilege_analysis': "🛡️ ANÁLISE DETALHADA DE EVENTOS DE PRIVILÉGIO:",
        'log_analyzer_detailed_complete': "✅ ANÁLISE DETALHADA CONCLUÍDA: {} eventos registrados",
        'log_analyzer_detailed_tip': "💡 Dica: Ative os filtros para focar apenas em atividades suspeitas",
    },
    
    'en_US': {
        # Interface principal
        'title': "WinLogZ - Windows Log Analyzer v1.0",
        'filter_checkbox': "[X] Filter false positives",
        'filter_active': "FILTERS ACTIVE",
        'filter_disabled': "FILTERS DISABLED",
        'analyze_button': "START LOGS ANALYSIS",
        'report_button': "GENERATE REPORT",
        'clear_button': "CLEAR CONSOLE",
        'status_ready': ">>> SYSTEM READY <<<",
        'status_analyzing': ">>> ANALYZING LOGS...",
        'status_complete': ">>> ANALYSIS COMPLETE: {} THREATS DETECTED",
        'status_complete_clean': ">>> ANALYSIS COMPLETE: SYSTEM CLEAN",
        'status_error': ">>> SYSTEM ERROR",

        'developed_by': "Developed by: João Pedro H. > Gitlab: @PHDevSec",
        
        # Mensagens de boas-vindas
        'welcome_title': ">>> WinLogZ - Windows Log Analyzer v1.0",
        'welcome_version': ">>> ADVANCED LOG ANALYSIS SYSTEM",
        'welcome_initializing': ">>> INITIALIZING SECURITY MODULES...",
        'welcome_access': "[GRANTED] SYSTEM LOGS ACCESS",
        'welcome_privilege': "[ADMINISTRATOR] ELEVATED PRIVILEGES CONFIRMED",
        'welcome_commands': ">>> AVAILABLE COMMANDS:",
        'welcome_analyze_desc': "  START LOGS ANALYSIS - Execute complete security scan",
        'welcome_report_desc': "  GENERATE REPORT - Generate detailed report",
        'welcome_clear_desc': "  CLEAR CONSOLE - Clear results console",
        
        
        # Mensagens de análise
        'analysis_starting': ">>> INITIATING SECURITY SCAN PROTOCOL",
        'config_filters_enabled': "[CONFIG] False positive filters: ENABLED",
        'config_system_events': "[CONFIG] Monitoring system events...",
        'config_filters_disabled': "[CONFIG] False positive filters: DISABLED",
        'config_showing_all': "[CONFIG] Showing all events...",
        
        # Resultados
        'results_summary': ">>> SCAN RESULTS SUMMARY",
        'results_mode_active': "[MODE] False positive filters: ACTIVE",
        'results_mode_inactive': "[MODE] False positive filters: INACTIVE",
        'results_total': "[TOTAL] {} activities detected",
        'results_high': "[HIGH] {} high severity threats",
        'results_medium': "[MEDIUM] {} medium severity threats", 
        'results_low': "[LOW] {} low severity threats",
        'results_threat_details': ">>> THREAT DETAILS",
        'results_threat': "--- THREAT {} [{}] ---",
        'results_type': "[TYPE] {}",
        'results_eventid': "[EVENT] {}",
        'results_time': "[TIME] {}",
        'results_description': "[DESCRIPTION] {}",
        'results_details': "[DETAILS]",
        'results_clean': "✅ No critical threats detected",
        'results_no_threats': "📊 System operating within normal parameters",
        'results_filters_working': "🛡️ Filters prevented false positives",
        'results_secure': "🔒 System considered secure",
        'results_complete': ">>> SECURITY SCAN COMPLETE",
        'results_ready': "Ready for next command...",
        
        # Erros
        'error_system': "❌ SYSTEM ERROR",
        'error_message': "💡 Details: {}",
        'error_permissions': "🔒 Check administrator permissions",
        'error_admin_required': "❌ Running without administrator privileges",
        'error_admin_suggestion': "💡 Run as administrator for full access",
        
        # Relatórios
        'report_generated': "📄 REPORT GENERATED SUCCESSFULLY",
        'report_file': "📁 File: {}",
        'report_location': "📂 Location: {}",
        'report_saved': "Report Saved",
        
        # Console
        'console_cleared': ">>> CONSOLE CLEARED",
        'console_ready': ">>> SYSTEM READY",
        'console_continue': ">>> AWAITING COMMANDS...",
        
        # Log Analyzer - Análise com filtros
        'log_analyzer_connecting': "🔍 Connecting to Windows log service...",
        'log_analyzer_reading_events': "📂 Reading security events...",
        'log_analyzer_processing_batch': "📦 Processing batch {} ({} events)...",
        'log_analyzer_collection_complete': "✅ Collection complete: {} events collected",
        'log_analyzer_access_error': "❌ Error accessing logs: {}",
        'log_analyzer_analyzing_failed_logins': "\n🔐 Analyzing failed login attempts...",
        'log_analyzer_failures_statistics': "   📊 Statistics: {} total failures, {} filtered",
        'log_analyzer_failures_statistics_no_filters': "   📊 Statistics: {} total failures (filters disabled)",
        'log_analyzer_checking_ips': "   🔎 Checking {} IPs...",
        'log_analyzer_possible_brute_force': "   🚨 POSSIBLE BRUTE FORCE: IP {} - {} attempts",
        'log_analyzer_trusted_ip_ignored': "   ✅ Trusted IP ignored: {}",
        'log_analyzer_normal_event': "   📍 Normal event: IP {} - {} attempts",
        'log_analyzer_analyzing_privilege_escalation': "\n🛡️ Analyzing privilege escalation events...",
        'log_analyzer_checking_eventid': "   🔍 Checking EventID {}...",
        'log_analyzer_filtered_noise': "   ⚡ Event {} filtered (common noise)",
        'log_analyzer_filtered_system_user': "   ⚡ Event {} filtered (system user: {})",
        'log_analyzer_filtered_system_process': "   ⚡ Event {} filtered (system process: {})",
        'log_analyzer_critical_event': "   🚨 CRITICAL EVENT: {}",
        'log_analyzer_suspicious_event': "   ⚠️  Event detected: {}",
        'log_analyzer_privilege_statistics': "   📊 Statistics: {} events, {} filtered, {} suspicious",
        'log_analyzer_privilege_statistics_no_filters': "   📊 Statistics: {} events detected (filters disabled)",
        'log_analyzer_starting_with_filters': "🚀 STARTING ANALYSIS WITH ACTIVE FILTERS",
        'log_analyzer_filters_note': "💡 False positives will be automatically filtered",
        'log_analyzer_starting_without_filters': "🚀 STARTING ANALYSIS WITH FILTERS DISABLED",
        'log_analyzer_no_filters_note': "💡 Showing ALL detected events",
        'log_analyzer_no_events': "❌ No events collected. Check permissions.",
        'log_analyzer_analyzing_events': "\n📈 Analyzing {} collected events...",
        'log_analyzer_analysis_complete_with_filters': "✅ ANALYSIS COMPLETE: {} suspicious activities after filters",
        'log_analyzer_analysis_complete_without_filters': "✅ ANALYSIS COMPLETE: {} activities detected (filters disabled)",
        'log_analyzer_brute_force_type': "Possible Brute Force Attack",
        'log_analyzer_brute_force_details': 'IP: {}, Attempts: {}',
        'log_analyzer_privilege_escalation_type': "Privilege Escalation",
        'log_analyzer_privilege_event_4672': "Special privileges assigned",
        'log_analyzer_privilege_event_4728': "Member added to delegation group",
        'log_analyzer_privilege_event_4732': "Member added to local administrators group",
        'log_analyzer_privilege_event_4735': "Security group changed",
        'log_analyzer_privilege_event_4670': "Object permissions changed",
        
        # Log Analyzer - Análise detalhada sem filtros
        'log_analyzer_detailed_mode': "📋 DETAILED MODE: Showing ALL collected events",
        'log_analyzer_detailed_analysis': "🔍 STARTING DETAILED ANALYSIS WITHOUT FILTERS",
        'log_analyzer_general_stats': "📊 GENERAL STATISTICS:",
        'log_analyzer_total_events': "   📈 Total events collected: {}",
        'log_analyzer_event_types': "   🏷️  Different event types: {}",
        'log_analyzer_failed_login_analysis': "🔐 DETAILED FAILED LOGIN ANALYSIS:",
        'log_analyzer_privilege_analysis': "🛡️ DETAILED PRIVILEGE EVENT ANALYSIS:",
        'log_analyzer_detailed_complete': "✅ DETAILED ANALYSIS COMPLETE: {} events recorded",
        'log_analyzer_detailed_tip': "💡 Tip: Enable filters to focus only on suspicious activities",
    },
    
    'es_ES': {
        # Interface principal
        'title': "WinLogZ - Windows Log Analyzer v1.0",
        'filter_checkbox': "[X] Filtrar falsos positivos",
        'filter_active': "FILTROS ACTIVOS",
        'filter_disabled': "FILTROS DESACTIVADOS",
        'analyze_button': "INICIAR ANÁLISIS DE REGISTROS",
        'report_button': "GENERAR INFORME",
        'clear_button': "LIMPIAR CONSOLA",
        'status_ready': ">>> SISTEMA LISTO <<<",
        'status_analyzing': ">>> ANALIZANDO REGISTROS...",
        'status_complete': ">>> ANÁLISIS COMPLETADO: {} AMENAZAS DETECTADAS",
        'status_complete_clean': ">>> ANÁLISIS COMPLETADO: SISTEMA LIMPIO",
        'status_error': ">>> ERROR DEL SISTEMA",

        'developed_by': "Desarrollado por: João Pedro H. > Gitlab: @PHDevSec",
        
        # Mensagens de boas-vindas
        'welcome_title': ">>> WinLogZ - Windows Log Analyzer v1.0",
        'welcome_version': ">>> SISTEMA AVANZADO DE ANÁLISIS DE REGISTROS",
        'welcome_initializing': ">>> INICIALIZANDO MÓDULOS DE SEGURIDAD...",
        'welcome_access': "[CONCEDIDO] ACCESO A LOS REGISTROS DEL SISTEMA",
        'welcome_privilege': "[ADMINISTRADOR] PRIVILEGIOS ELEVADOS CONFIRMADOS",
        'welcome_commands': ">>> COMANDOS DISPONIBLES:",
        'welcome_analyze_desc': "  INICIAR ANÁLISIS DE REGISTROS - Ejecutar escaneo de seguridad completo",
        'welcome_report_desc': "  GENERAR INFORME - Generar informe detallado",
        'welcome_clear_desc': "  LIMPIAR CONSOLA - Limpiar consola de resultados",
        
        
        # Mensagens de análise
        'analysis_starting': ">>> INICIANDO PROTOCOLO DE ESCANEO DE SEGURIDAD",
        'config_filters_enabled': "[CONFIG] Filtros de falsos positivos: ACTIVADOS",
        'config_system_events': "[CONFIG] Monitoreando eventos del sistema...",
        'config_filters_disabled': "[CONFIG] Filtros de falsos positivos: DESACTIVADOS",
        'config_showing_all': "[CONFIG] Mostrando todos los eventos...",
        
        # Resultados
        'results_summary': ">>> RESUMEN DE RESULTADOS DEL ESCANEO",
        'results_mode_active': "[MODO] Filtros de falsos positivos: ACTIVO",
        'results_mode_inactive': "[MODO] Filtros de falsos positivos: INACTIVO",
        'results_total': "[TOTAL] {} actividades detectadas",
        'results_high': "[ALTO] {} amenazas de alta severidad",
        'results_medium': "[MEDIO] {} amenazas de media severidad", 
        'results_low': "[BAJO] {} amenazas de baja severidad",
        'results_threat_details': ">>> DETALLES DE AMENAZAS",
        'results_threat': "--- AMENAZA {} [{}] ---",
        'results_type': "[TIPO] {}",
        'results_eventid': "[EVENTO] {}",
        'results_time': "[HORA] {}",
        'results_description': "[DESCRIPCIÓN] {}",
        'results_details': "[DETALLES]",
        'results_clean': "✅ No se detectaron amenazas críticas",
        'results_no_threats': "📊 Sistema operando dentro de parámetros normales",
        'results_filters_working': "🛡️ Los filtros previenen falsos positivos",
        'results_secure': "🔒 Sistema considerado seguro",
        'results_complete': ">>> ESCANEO DE SEGURIDAD COMPLETADO",
        'results_ready': "Listo para el siguiente comando...",
        
        # Erros
        'error_system': "❌ ERROR DEL SISTEMA",
        'error_message': "💡 Detalles: {}",
        'error_permissions': "🔒 Verifique los permisos de administrador",
        'error_admin_required': "❌ Ejecución sin privilegios de administrador",
        'error_admin_suggestion': "💡 Ejecute como administrador para acceso completo",
        
        # Relatórios
        'report_generated': "📄 INFORME GENERADO CON ÉXITO",
        'report_file': "📁 Archivo: {}",
        'report_location': "📂 Ubicación: {}",
        'report_saved': "Informe Guardado",
        
        # Console
        'console_cleared': ">>> CONSOLA LIMPIADA",
        'console_ready': ">>> SISTEMA LISTO",
        'console_continue': ">>> ESPERANDO COMANDOS...",
        
        # Log Analyzer - Análise com filtros
        'log_analyzer_connecting': "🔍 Conectando al servicio de logs de Windows...",
        'log_analyzer_reading_events': "📂 Leyendo eventos de seguridad...",
        'log_analyzer_processing_batch': "📦 Procesando lote {} ({} eventos)...",
        'log_analyzer_collection_complete': "✅ Colección completada: {} eventos recolectados",
        'log_analyzer_access_error': "❌ Error accediendo a logs: {}",
        'log_analyzer_analyzing_failed_logins': "\n🔐 Analizando intentos de login fallidos...",
        'log_analyzer_failures_statistics': "   📊 Estadísticas: {} fallos totales, {} filtrados",
        'log_analyzer_failures_statistics_no_filters': "   📊 Estadísticas: {} fallos totales (filtros desactivados)",
        'log_analyzer_checking_ips': "   🔎 Verificando {} IPs...",
        'log_analyzer_possible_brute_force': "   🚨 POSIBLE FUERZA BRUTA: IP {} - {} intentos",
        'log_analyzer_trusted_ip_ignored': "   ✅ IP confiable ignorado: {}",
        'log_analyzer_normal_event': "   📍 Evento normal: IP {} - {} intentos",
        'log_analyzer_analyzing_privilege_escalation': "\n🛡️ Analizando eventos de escalada de privilegios...",
        'log_analyzer_checking_eventid': "   🔍 Verificando EventID {}...",
        'log_analyzer_filtered_noise': "   ⚡ Evento {} filtrado (ruido común)",
        'log_analyzer_filtered_system_user': "   ⚡ Evento {} filtrado (usuario del sistema: {})",
        'log_analyzer_filtered_system_process': "   ⚡ Evento {} filtrado (proceso del sistema: {})",
        'log_analyzer_critical_event': "   🚨 EVENTO CRÍTICO: {}",
        'log_analyzer_suspicious_event': "   ⚠️  Evento detectado: {}",
        'log_analyzer_privilege_statistics': "   📊 Estadísticas: {} eventos, {} filtrados, {} sospechosos",
        'log_analyzer_privilege_statistics_no_filters': "   📊 Estadísticas: {} eventos detectados (filtros desactivados)",
        'log_analyzer_starting_with_filters': "🚀 INICIANDO ANÁLISIS CON FILTROS ACTIVOS",
        'log_analyzer_filters_note': "💡 Los falsos positivos serán filtrados automáticamente",
        'log_analyzer_starting_without_filters': "🚀 INICIANDO ANÁLISIS CON FILTROS DESACTIVADOS",
        'log_analyzer_no_filters_note': "💡 Mostrando TODOS los eventos detectados",
        'log_analyzer_no_events': "❌ No se recolectaron eventos. Verifique los permisos.",
        'log_analyzer_analyzing_events': "\n📈 Analizando {} eventos recolectados...",
        'log_analyzer_analysis_complete_with_filters': "✅ ANÁLISIS COMPLETADO: {} actividades sospechosas después de filtros",
        'log_analyzer_analysis_complete_without_filters': "✅ ANÁLISIS COMPLETADO: {} actividades detectadas (filtros desactivados)",
        'log_analyzer_brute_force_type': "Posible Ataque de Fuerza Bruta",
        'log_analyzer_brute_force_details': 'IP: {}, Intentos: {}',
        'log_analyzer_privilege_escalation_type': "Escalada de Privilegios",
        'log_analyzer_privilege_event_4672': "Privilegios especiales asignados",
        'log_analyzer_privilege_event_4728': "Miembro añadido al grupo de delegación",
        'log_analyzer_privilege_event_4732': "Miembro añadido al grupo de administradores locales",
        'log_analyzer_privilege_event_4735': "Grupo de seguridad cambiado",
        'log_analyzer_privilege_event_4670': "Permisos de objeto cambiados",
        
        # Log Analyzer - Análise detalhada sem filtros
        'log_analyzer_detailed_mode': "📋 MODO DETALLADO: Mostrando TODOS los eventos recolectados",
        'log_analyzer_detailed_analysis': "🔍 INICIANDO ANÁLISIS DETALLADO SIN FILTROS",
        'log_analyzer_general_stats': "📊 ESTADÍSTICAS GENERALES:",
        'log_analyzer_total_events': "   📈 Total de eventos recolectados: {}",
        'log_analyzer_event_types': "   🏷️  Tipos de eventos diferentes: {}",
        'log_analyzer_failed_login_analysis': "🔐 ANÁLISIS DETALLADO DE FALLOS DE LOGIN:",
        'log_analyzer_privilege_analysis': "🛡️ ANÁLISIS DETALLADO DE EVENTOS DE PRIVILEGIO:",
        'log_analyzer_detailed_complete': "✅ ANÁLISIS DETALLADO COMPLETADO: {} eventos registrados",
        'log_analyzer_detailed_tip': "💡 Consejo: Active los filtros para enfocarse solo en actividades sospechosas",
    }
}

class LanguageManager:
    def __init__(self, language='pt_BR'):
        self.language = language
        self.strings = LANGUAGES.get(language, LANGUAGES['pt_BR'])
    
    def set_language(self, language):
        if language in LANGUAGES:
            self.language = language
            self.strings = LANGUAGES[language]
            return True
        return False
    
    def get(self, key):
        return self.strings.get(key, f"[{key}]")
    
    def get_text(self, key, *args):
        text = self.strings.get(key, f"[{key}]")
        if args:
            try:
                return text.format(*args)
            except:
                return text
        return text
    
    def get_available_languages(self):
        return list(LANGUAGES.keys())
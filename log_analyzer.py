import win32evtlog
import pandas as pd
from datetime import datetime, timedelta
import re

class LogAnalyzer:
    def __init__(self, log_callback=None, enable_filters=True, language_manager=None):
        self.suspicious_activities = []
        self.log_callback = log_callback
        self.enable_filters = enable_filters
        self.language_manager = language_manager
        
        # CONFIGURAÇÕES DE FILTRO
        self.filter_config = {
            'trusted_ips': ['192.168.1.1', '192.168.1.2', '127.0.0.1'],
            'trusted_hosts': ['DC01', 'SERVER01', 'WSUS'],
            'trusted_users': ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'Administrador'],
            'trusted_processes': ['svchost.exe', 'msmpeng.exe', 'winlogon.exe'],
            'noisy_events': [4624, 4634],
            'business_hours': {'start': 8, 'end': 18},
            'failed_login_threshold': 10,
            'brute_force_timeframe': 30
        }
    
    def t(self, key, *args):
        """Método auxiliar para traduzir textos"""
        if self.language_manager:
            return self.language_manager.get_text(key, *args)
        else:
            # Fallback em português
            fallback_texts = {
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
                'log_analyzer_detailed_mode': "📋 MODO DETALHADO: Mostrando TODOS os eventos coletados",
                'log_analyzer_detailed_analysis': "🔍 INICIANDO ANÁLISE DETALHADA SEM FILTROS",
                'log_analyzer_general_stats': "📊 ESTATÍSTICAS GERAIS:",
                'log_analyzer_total_events': "   📈 Total de eventos coletados: {}",
                'log_analyzer_event_types': "   🏷️  Tipos de eventos diferentes: {}",
                'log_analyzer_failed_login_analysis': "🔐 ANÁLISE DETALHADA DE FALHAS DE LOGIN:",
                'log_analyzer_privilege_analysis': "🛡️ ANÁLISE DETALHADA DE EVENTOS DE PRIVILÉGIO:",
                'log_analyzer_detailed_complete': "✅ ANÁLISE DETALHADA CONCLUÍDA: {} eventos registrados",
                'log_analyzer_detailed_tip': "💡 Dica: Ative os filtros para focar apenas em atividades suspeitas",
            }
            if key in fallback_texts:
                text = fallback_texts[key]
                if args:
                    return text.format(*args)
                return text
            return key
    
    def log(self, message):
        """Envia mensagem para a interface se callback estiver definido"""
        if self.log_callback:
            self.log_callback(message)
    
    def get_security_logs(self, hours_back=24):
        """Coleta logs de segurança com feedback em tempo real"""
        self.log(self.t('log_analyzer_connecting'))
        try:
            server = 'localhost'
            logtype = 'Security'
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = []
            
            cutoff_time = datetime.now() - timedelta(hours=hours_back)
            batch_count = 0
            
            self.log(self.t('log_analyzer_reading_events'))
            
            while True:
                events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events_batch:
                    break
                
                batch_count += 1
                self.log(self.t('log_analyzer_processing_batch', batch_count, len(events_batch)))
                
                for event in events_batch:
                    if event.TimeGenerated < cutoff_time:
                        win32evtlog.CloseEventLog(hand)
                        self.log(self.t('log_analyzer_collection_complete', len(events)))
                        return events
                    
                    events.append({
                        'EventID': event.EventID,
                        'TimeGenerated': event.TimeGenerated,
                        'SourceName': event.SourceName,
                        'Strings': event.StringInserts or []
                    })
            
            win32evtlog.CloseEventLog(hand)
            self.log(self.t('log_analyzer_collection_complete', len(events)))
            return events
            
        except Exception as e:
            error_msg = str(e)
            if "acesso negado" in error_msg.lower() or "access denied" in error_msg.lower():
                self.log("❌ ACESSO NEGADO: Privilégios de administrador necessários")
                self.log("💡 Execute o programa como administrador")
            else:
                self.log(self.t('log_analyzer_access_error', e))
            return []
    
    def is_false_positive(self, event):
        """Verifica se um evento é provavelmente falso positivo com logging"""
        # Se filtros estão desativados, nunca considerar como falso positivo
        if not self.enable_filters:
            return False
            
        event_id = event.get('EventID', 0)
        event_details = str(event.get('Strings', [])).lower()
        
        # 1. Filtra os Event IDs comuns (ruído)
        if event_id in self.filter_config['noisy_events']:
            self.log(self.t('log_analyzer_filtered_noise', event_id))
            return True
        
        # 2. Filtra as atividades de usuários do sistema
        for trusted_user in self.filter_config['trusted_users']:
            if trusted_user.lower() in event_details:
                self.log(self.t('log_analyzer_filtered_system_user', event_id, trusted_user))
                return True
        
        # 3. Filtra por processos do sistema
        for trusted_process in self.filter_config['trusted_processes']:
            if trusted_process.lower() in event_details:
                self.log(self.t('log_analyzer_filtered_system_process', event_id, trusted_process))
                return True
        
        return False
    
    def analyze_failed_logins_intelligently(self, events):
        """Análise inteligente de logins falhos com feedback detalhado"""
        self.log(self.t('log_analyzer_analyzing_failed_logins'))
        failed_logins_by_ip = {}
        suspicious_failures = []
        total_failures = 0
        filtered_failures = 0
        
        for event in events:
            if event['EventID'] == 4625:  # Falha no login
                total_failures += 1
                
                # Pular falsos positivos (só se filtros estiverem ativos)
                if self.is_false_positive(event):
                    filtered_failures += 1
                    continue
                
                # Extrai IP dos detalhes do evento
                ip_address = self.extract_ip_from_event(event)
                if not ip_address:
                    continue
                
                # Ignora os IPs confiáveis (só se filtros estiverem ativos)
                if self.enable_filters and ip_address in self.filter_config['trusted_ips']:
                    self.log(self.t('log_analyzer_trusted_ip_ignored', ip_address))
                    continue
                
                # Conta as tentativas por IP
                if ip_address not in failed_logins_by_ip:
                    failed_logins_by_ip[ip_address] = []
                failed_logins_by_ip[ip_address].append(event['TimeGenerated'])
        
        # Mostra as estatísticas baseadas na configuração de filtros
        if self.enable_filters:
            self.log(self.t('log_analyzer_failures_statistics', total_failures, filtered_failures))
        else:
            self.log(self.t('log_analyzer_failures_statistics_no_filters', total_failures))
        
        # Analisa os padrões de força bruta
        self.log(self.t('log_analyzer_checking_ips', len(failed_logins_by_ip)))
        for ip, timestamps in failed_logins_by_ip.items():
            if self.is_brute_force_pattern(timestamps):
                self.log(self.t('log_analyzer_possible_brute_force', ip, len(timestamps)))
                suspicious_failures.append({
                    'Tipo': self.t('log_analyzer_brute_force_type'),
                    'EventID': 4625,
                    'Horário': timestamps[-1],
                    'Detalhes': self.t('log_analyzer_brute_force_details', ip, len(timestamps)),
                    'Severidade': 'High'
                })
            else:
                if not self.enable_filters:
                    self.log(self.t('log_analyzer_normal_event', ip, len(timestamps)))
        
        return suspicious_failures
    
    def analyze_privilege_escalation_with_context(self, events):
        """Análise de escalação de privilégios com logging otimizado"""
        self.log(self.t('log_analyzer_analyzing_privilege_escalation'))
        
        privilege_events = {
            4672: self.t('log_analyzer_privilege_event_4672'),
            4728: self.t('log_analyzer_privilege_event_4728'), 
            4732: self.t('log_analyzer_privilege_event_4732'),
            4735: self.t('log_analyzer_privilege_event_4735'),
            4670: self.t('log_analyzer_privilege_event_4670')
        }
        
        suspicious_events = []
        total_events = 0
        filtered_events = 0
        
        # Agrupa os eventos por tipo para evitar logs repetitivos
        events_by_type = {}
        for event in events:
            event_id = event['EventID']
            if event_id in privilege_events:
                total_events += 1
                if event_id not in events_by_type:
                    events_by_type[event_id] = []
                events_by_type[event_id].append(event)
        
        # Processa cada tipo de evento uma vez
        for event_id, event_list in events_by_type.items():
            self.log(self.t('log_analyzer_checking_eventid', event_id))
            
            event_count = len(event_list)
            filtered_count = 0
            suspicious_count = 0
            
            for event in event_list:
                if self.is_false_positive(event):
                    filtered_count += 1
                    continue
                
                suspicious_count += 1
                
                # Adiciona apenas uma amostra de cada tipo para evitar duplicação
                if suspicious_count <= 2:  # Máximo 2 eventos por tipo
                    severity = "High" if event_id in [4732, 4672] else "Medium"
                    
                    # Resume detalhes do evento
                    event_details = self.summarize_event_details(event)
                    
                    suspicious_events.append({
                        'Tipo': self.t('log_analyzer_privilege_escalation_type'),
                        'EventID': event_id,
                        'Descrição': privilege_events[event_id],
                        'Horário': event['TimeGenerated'],
                        'Detalhes': event_details,
                        'Severidade': severity
                    })
            
            filtered_events += filtered_count
            
            # Mostra o resumo para este tipo de evento
            if suspicious_count > 0:
                if event_id in [4732, 4672]:
                    self.log(f"   🚨 {suspicious_count} eventos críticos de {privilege_events[event_id]}")
                else:
                    self.log(f"   ⚠️  {suspicious_count} eventos suspeitos de {privilege_events[event_id]}")
            else:
                self.log(f"   ✅ Nenhum evento suspeito de {privilege_events[event_id]}")
        
        # Mostra as estatísticas apropriadas
        if self.enable_filters:
            self.log(self.t('log_analyzer_privilege_statistics', total_events, filtered_events, len(suspicious_events)))
        else:
            self.log(self.t('log_analyzer_privilege_statistics_no_filters', total_events))
        
        return suspicious_events
    
    def summarize_event_details(self, event):
        """Resume os detalhes do evento para evitar repetição"""
        strings = event.get('Strings', [])
        if not strings:
            return "Sem detalhes disponíveis"
        
        # Extrai as informações relevantes baseadas no tipo de evento
        event_id = event.get('EventID', 0)
        
        if event_id == 4672:  # Atribuição de privilégios especiais
            if len(strings) > 1:
                user = strings[1] if len(strings) > 1 else "N/A"
                privilege = strings[3] if len(strings) > 3 else "N/A"
                return f"Usuário: {user}, Privilégio: {privilege}"
        
        elif event_id in [4728, 4732, 4735]:  # Eventos de grupo
            if len(strings) > 1:
                target_user = strings[0] if len(strings) > 0 else "N/A"
                group = strings[2] if len(strings) > 2 else "N/A"
                return f"Usuário: {target_user}, Grupo: {group}"
        
        # Fallback: retornar primeiros detalhes relevantes
        relevant_strings = [s for s in strings if s and len(s) < 50]  # Filtrar strings muito longas
        return ", ".join(relevant_strings[:3])  # Retornar apenas os 3 primeiros detalhes
    
    def comprehensive_analysis(self):
        """Executa análise completa com feedback detalhado"""
        # Mostra modo atual
        if self.enable_filters:
            self.log(self.t('log_analyzer_starting_with_filters'))
            self.log(self.t('log_analyzer_filters_note'))
        else:
            self.log(self.t('log_analyzer_starting_without_filters'))
            self.log(self.t('log_analyzer_no_filters_note'))
            self.log(self.t('log_analyzer_detailed_mode'))
            
        self.log("=" * 50)
        
        events = self.get_security_logs(hours_back=24)
        
        if not events:
            self.log(self.t('log_analyzer_no_events'))
            return []
        
        self.log(self.t('log_analyzer_analyzing_events', len(events)))
        
        # Se filtros estão desativados, mostrar análise detalhada
        if not self.enable_filters:
            return self.detailed_analysis_without_filters(events)
        
        # Executa as análises específicas com filtros
        privilege_issues = self.analyze_privilege_escalation_with_context(events)
        failed_logins = self.analyze_failed_logins_intelligently(events)
        
        # Combina os resultados
        all_findings = privilege_issues + failed_logins
        
        # Ordena por severidade
        severity_order = {'High': 3, 'Medium': 2, 'Low': 1}
        all_findings.sort(key=lambda x: severity_order.get(x.get('Severidade', 'Low'), 1), reverse=True)
        
        self.log("\n" + "=" * 50)
        
        # Mensagem final baseada na configuração
        if self.enable_filters:
            self.log(self.t('log_analyzer_analysis_complete_with_filters', len(all_findings)))
        else:
            self.log(self.t('log_analyzer_analysis_complete_without_filters', len(all_findings)))
        
        return all_findings
    
    def detailed_analysis_without_filters(self, events):
        """Análise detalhada mostrando TODOS os eventos quando filtros estão desativados"""
        self.log("\n" + self.t('log_analyzer_detailed_analysis'))
        self.log("=" * 60)
        
        all_events_by_type = {}
        total_events = len(events)
        
        # Agrupa todos os eventos por tipo
        for event in events:
            event_id = event['EventID']
            if event_id not in all_events_by_type:
                all_events_by_type[event_id] = []
            all_events_by_type[event_id].append(event)
        
        # Mostra as estatísticas gerais
        self.log(self.t('log_analyzer_general_stats'))
        self.log(self.t('log_analyzer_total_events', total_events))
        self.log(self.t('log_analyzer_event_types', len(all_events_by_type)))
        
        # Lista de eventos importantes para mostrar detalhes
        important_events = {
            4624: "Logon bem-sucedido",
            4625: "Falha no logon", 
            4634: "Logoff",
            4648: "Logon com credenciais explícitas",
            4672: "Privilégios especiais atribuídos",
            4728: "Membro adicionado ao grupo de delegação",
            4732: "Membro adicionado ao grupo de administradores locais",
            4735: "Grupo de segurança alterado",
            4670: "Permissões de objeto alteradas",
            4649: "Tentativa de replay de ataque detectado",
            4657: "Alteração no registro do sistema",
            4663: "Acesso a objeto",
            4688: "Novo processo criado",
            4697: "Serviço instalado no sistema",
            4702: "Tarefa agendada atualizada",
            4719: "Política de auditoria do sistema alterada",
            4720: "Conta de usuário criada",
            4738: "Conta de usuário alterada",
            4740: "Conta de usuário bloqueada",
            4776: "Controlador de domínio validou as credenciais",
            4798: "Enumeração de grupos de usuários",
            4897: "Isolamento de função e recurso alterado"
        }
        
        detailed_findings = []
        
        # Mostra detalhes de eventos importantes
        for event_id, description in important_events.items():
            if event_id in all_events_by_type:
                events_list = all_events_by_type[event_id]
                event_count = len(events_list)
                
                self.log(f"\n📋 Evento {event_id}: {description}")
                self.log(f"   📊 Ocorrências: {event_count}")
                
                # Mostra amostras dos eventos (máximo 3)
                sample_count = min(3, event_count)
                for i in range(sample_count):
                    event = events_list[i]
                    event_time = event['TimeGenerated'].strftime("%Y-%m-%d %H:%M:%S") if hasattr(event['TimeGenerated'], 'strftime') else str(event['TimeGenerated'])
                    
                    # Extrai informações relevantes
                    details = self.extract_event_details(event)
                    
                    self.log(f"   🕐 Amostra {i+1}: {event_time}")
                    self.log(f"      {details}")
                    
                    # Adiciona aos findings
                    severity = self.determine_event_severity(event_id)
                    detailed_findings.append({
                        'Tipo': description,
                        'EventID': event_id,
                        'Descrição': description,
                        'Horário': event_time,
                        'Detalhes': details,
                        'Severidade': severity
                    })
                
                if event_count > sample_count:
                    self.log(f"   ... e mais {event_count - sample_count} ocorrências")
        
        # Análises específicas (mesmo sem filtros)
        self.log("\n" + "=" * 50)
        self.log("🎯 ANÁLISES ESPECÍFICAS:")
        
        # Análise de falhas de login (sem filtros)
        failed_logins = self.analyze_failed_logins_detailed(events)
        detailed_findings.extend(failed_logins)
        
        # Análise de privilégios (sem filtros)
        privilege_events = self.analyze_privilege_events_detailed(events)
        detailed_findings.extend(privilege_events)
        
        self.log("\n" + "=" * 60)
        self.log(self.t('log_analyzer_detailed_complete', len(detailed_findings)))
        self.log(self.t('log_analyzer_detailed_tip'))
        
        return detailed_findings
    
    def analyze_failed_logins_detailed(self, events):
        """Análise detalhada de falhas de login sem filtros"""
        self.log("\n" + self.t('log_analyzer_failed_login_analysis'))
        
        failed_logins = [e for e in events if e['EventID'] == 4625]
        total_failures = len(failed_logins)
        
        self.log(f"   📊 Total de falhas de login: {total_failures}")
        
        if not failed_logins:
            return []
        
        # Agrupa por IP
        failures_by_ip = {}
        for event in failed_logins:
            ip = self.extract_ip_from_event(event)
            if ip:
                if ip not in failures_by_ip:
                    failures_by_ip[ip] = []
                failures_by_ip[ip].append(event)
        
        # Mostra as estatísticas por IP
        self.log(f"   🌐 IPs distintos com falhas: {len(failures_by_ip)}")
        
        findings = []
        for ip, ip_events in failures_by_ip.items():
            attempt_count = len(ip_events)
            last_attempt = ip_events[-1]['TimeGenerated']
            last_time = last_attempt.strftime("%Y-%m-%d %H:%M:%S") if hasattr(last_attempt, 'strftime') else str(last_attempt)
            
            self.log(f"   🔍 IP {ip}: {attempt_count} tentativas (última: {last_time})")
            
            findings.append({
                'Tipo': "Falha de Login Detalhada",
                'EventID': 4625,
                'Descrição': f"Falhas de login do IP {ip}",
                'Horário': last_time,
                'Detalhes': f"IP: {ip}, Tentativas: {attempt_count}, Última: {last_time}",
                'Severidade': 'Medium' if attempt_count > 5 else 'Low'
            })
        
        return findings
    
    def analyze_privilege_events_detailed(self, events):
        """Análise detalhada de eventos de privilégio sem filtros"""
        self.log("\n" + self.t('log_analyzer_privilege_analysis'))
        
        privilege_event_ids = [4672, 4728, 4732, 4735, 4670]
        privilege_events = [e for e in events if e['EventID'] in privilege_event_ids]
        
        self.log(f"   📊 Total de eventos de privilégio: {len(privilege_events)}")
        
        findings = []
        for event in privilege_events[:10]:  # Limita a 10 para não poluir
            event_id = event['EventID']
            event_time = event['TimeGenerated'].strftime("%Y-%m-%d %H:%M:%S") if hasattr(event['TimeGenerated'], 'strftime') else str(event['TimeGenerated'])
            
            description = self.get_privilege_event_description(event_id)
            details = self.extract_event_details(event)
            
            self.log(f"   🔍 Evento {event_id}: {description}")
            self.log(f"      🕐 {event_time}")
            self.log(f"      📝 {details}")
            
            findings.append({
                'Tipo': "Evento de Privilégio Detalhado",
                'EventID': event_id,
                'Descrição': description,
                'Horário': event_time,
                'Detalhes': details,
                'Severidade': 'High' if event_id in [4732, 4672] else 'Medium'
            })
        
        return findings
    
    def extract_event_details(self, event):
        """Extrai detalhes legíveis do evento"""
        strings = event.get('Strings', [])
        if not strings:
            return "Sem detalhes disponíveis"
        
        event_id = event.get('EventID', 0)
        
        # Mapeia os detalhes baseados no tipo de evento
        if event_id == 4624:  # Logon bem-sucedido
            if len(strings) > 5:
                return f"Usuário: {strings[5]}, Domínio: {strings[6]}, Tipo: {strings[8]}"
        
        elif event_id == 4625:  # Falha no logon
            if len(strings) > 5:
                return f"Usuário: {strings[5]}, Domínio: {strings[6]}, Status: {strings[7]}"
        
        elif event_id == 4672:  # Privilégios especiais
            if len(strings) > 1:
                return f"Usuário: {strings[1]}, Privilégio: {strings[3]}"
        
        # Fallback: retornar strings relevantes
        relevant = [s for s in strings if s and len(s) < 100]
        return ", ".join(relevant[:4])
    
    def get_privilege_event_description(self, event_id):
        """Retorna descrição para eventos de privilégio"""
        descriptions = {
            4672: "Atribuição de privilégios especiais",
            4728: "Membro adicionado ao grupo de delegação", 
            4732: "Membro adicionado ao grupo de administradores locais",
            4735: "Grupo de segurança alterado",
            4670: "Permissões de objeto alteradas"
        }
        return descriptions.get(event_id, f"Evento {event_id}")
    
    def determine_event_severity(self, event_id):
        """Determina a severidade baseada no tipo de evento"""
        high_severity = [4625, 4672, 4732, 4735, 4670]  # Falhas e privilégios
        medium_severity = [4728, 4648, 4697]  # Alterações importantes
        
        if event_id in high_severity:
            return 'High'
        elif event_id in medium_severity:
            return 'Medium'
        else:
            return 'Low'
    
    def extract_ip_from_event(self, event):
        """Extrai endereço IP dos detalhes do evento"""
        try:
            strings = event.get('Strings', [])
            if strings and len(strings) > 19:
                ip = strings[19]
                if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                    return ip
        except:
            pass
        return None
    
    def is_brute_force_pattern(self, timestamps):
        """Identifica padrões de força bruta baseado em tempo"""
        if len(timestamps) < self.filter_config['failed_login_threshold']:
            return False
        
        timestamps.sort()
        time_window = self.filter_config['brute_force_timeframe']
        window_start = timestamps[-1] - timedelta(minutes=time_window)
        attempts_in_window = sum(1 for ts in timestamps if ts > window_start)
        
        return attempts_in_window >= self.filter_config['failed_login_threshold']
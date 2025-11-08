import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import os
from datetime import datetime
import ctypes
import sys

try:
    from log_analyzer import LogAnalyzer
    from language_manager import LanguageManager
except ImportError as e:
    print(f"Erro de importação: {e}")
    LogAnalyzer = None
    LanguageManager = None

def is_admin():
    """
    Verifica se o programa está sendo executado com privilégios de administrador
    Retorna: bool - True se for admin, False caso contrário
    """
    try:
        # Método para Windows
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        # Fallback para outros sistemas ou em caso de erro
        try:
            # Para Linux/Mac, verifica se o UID é 0 (root)
            return os.geteuid() == 0
        except:
            # Se tudo falhar, assume que não é admin
            return False

class Winlogz:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("WinLogZ - Windows Log Analyzer v1.0")
        self.root.geometry("1000x700")
        self.root.configure(bg='black')
        
        # Inicializa o gerenciador de idiomas
        self.lang = LanguageManager()
        self.analyzer = None
        self.current_content = []  # Para armazenar o conteúdo atual do console
        
        self.setup_ui()
    
    def setup_ui(self):
        # Cores do tema Matrix/Terminal Linux
        self.colors = {
            'bg_primary': '#000000',
            'bg_secondary': '#001100',
            'bg_button': '#003300',
            'bg_button_hover': '#005500',
            'text_primary': '#00ff00',
            'success': '#00ff00',
            'warning': '#ffff00',
            'error': '#ff0000',
        }
        
        # Título
        self.title_label = tk.Label(
            self.root,
            text=self.lang.get_text('title'),
            font=("Consolas", 14, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_primary']
        )
        self.title_label.pack(pady=10)
        
        # ========== LINHA SUPERIOR: IDIOMA E CRÉDITO ==========
        top_row_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        top_row_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Idioma ao Centro
        language_frame = tk.Frame(top_row_frame, bg=self.colors['bg_primary'])
        language_frame.pack(anchor=tk.CENTER)
        
        language_label = tk.Label(
            language_frame,
            text=">_ LANG:",
            font=("Consolas", 9, "bold"),
            bg=self.colors['bg_primary'],
            fg=self.colors['text_primary']
        )
        language_label.pack(anchor=tk.CENTER)
        
        # Menu de idioma estilo terminal/matrix
        self.language_var = tk.StringVar(value='PT-BR')
        self.language_menu = tk.Menubutton(
            language_frame,
            textvariable=self.language_var,
            font=("Consolas", 9),
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary'],
            activebackground=self.colors['bg_button_hover'],
            activeforeground='#ffffff',
            relief="flat",
            bd=1,
            cursor='xterm',
            width=8
        )
        self.language_menu.pack(anchor=tk.CENTER, padx=5)
        
        # Cria o menu dropdown
        self.language_dropdown = tk.Menu(
            self.language_menu,
            tearoff=0,
            bg='#001100',
            fg='#00ff00',
            activebackground='#005500',
            activeforeground='#ffffff',
            font=("Consolas", 9),
            bd=1,
            relief="flat"
        )
        
        # Adiciona as opções de idioma
        self.language_dropdown.add_command(
            label="PT-BR",
            command=lambda: self.on_language_change('PT-BR', 'pt_BR')
        )
        self.language_dropdown.add_command(
            label="EN-US", 
            command=lambda: self.on_language_change('EN-US', 'en_US')
        )
        self.language_dropdown.add_command(
            label="ES-ES",
            command=lambda: self.on_language_change('ES-ES', 'es_ES')
        )
        
        self.language_menu.config(menu=self.language_dropdown)
        
        # Adiciona o efeito hover ao botão de idioma
        self.language_menu.bind("<Enter>", lambda e: self.language_menu.config(
            bg=self.colors['bg_button_hover'],
            fg='#ffffff'
        ))
        self.language_menu.bind("<Leave>", lambda e: self.language_menu.config(
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary']
        ))
        
        # Crédito à direita
        credits_frame = tk.Frame(top_row_frame, bg=self.colors['bg_primary'])
        credits_frame.pack(side=tk.RIGHT)
        
        self.credits_label = tk.Label(
            credits_frame,
            text=self.lang.get_text('developed_by'),
            font=("Consolas", 8, "bold"),
            bg=self.colors['bg_primary'],
            fg='#FFFF00'
        )
        self.credits_label.pack(side=tk.RIGHT)
        
        # ========== FILTROS CENTRALIZADOS ==========
        filter_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        filter_frame.pack(pady=10)
        
        # Checkbox de filtros
        self.enable_filters = tk.BooleanVar(value=True)
        self.filter_checkbox = tk.Checkbutton(
            filter_frame,
            text=self.lang.get_text('filter_checkbox'),
            variable=self.enable_filters,
            font=("Consolas", 9),
            command=self.on_filter_toggle,
            bg=self.colors['bg_primary'],
            fg=self.colors['text_primary'],
            selectcolor=self.colors['bg_secondary'],
            activebackground=self.colors['bg_primary'],
            activeforeground=self.colors['text_primary']
        )
        self.filter_checkbox.pack(side=tk.LEFT, padx=10)
        
        # Status dos filtros
        self.filter_status = tk.Label(
            filter_frame,
            text=self.lang.get_text('filter_active'),
            fg=self.colors['success'],
            bg=self.colors['bg_primary'],
            font=("Consolas", 9, "bold")
        )
        self.filter_status.pack(side=tk.LEFT, padx=10)
        
        # ========== BOTÕES PRINCIPAIS ==========
        button_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        button_frame.pack(pady=10)
        
        # Botões principais
        self.analyze_btn = tk.Button(
            button_frame,
            text=self.lang.get_text('analyze_button'),
            command=self.start_analysis,
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary'],
            font=("Consolas", 9),
            width=30,
            relief="flat"
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=5)
        
        # Efeito hover para botão de análise
        self.analyze_btn.bind("<Enter>", lambda e: self.analyze_btn.config(
            bg=self.colors['bg_button_hover'],
            fg='#ffffff'
        ))
        self.analyze_btn.bind("<Leave>", lambda e: self.analyze_btn.config(
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary']
        ))
        
        self.report_btn = tk.Button(
            button_frame,
            text=self.lang.get_text('report_button'),
            command=self.generate_report,
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary'],
            font=("Consolas", 9),
            width=20,
            relief="flat"
        )
        self.report_btn.pack(side=tk.LEFT, padx=5)
        
        # Efeito hover para botão de relatório
        self.report_btn.bind("<Enter>", lambda e: self.report_btn.config(
            bg=self.colors['bg_button_hover'],
            fg='#ffffff'
        ))
        self.report_btn.bind("<Leave>", lambda e: self.report_btn.config(
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary']
        ))
        
        self.clear_btn = tk.Button(
            button_frame,
            text=self.lang.get_text('clear_button'),
            command=self.clear_results,
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary'],
            font=("Consolas", 9),
            width=15,
            relief="flat"
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Efeito hover para botão de limpar
        self.clear_btn.bind("<Enter>", lambda e: self.clear_btn.config(
            bg=self.colors['bg_button_hover'],
            fg='#ffffff'
        ))
        self.clear_btn.bind("<Leave>", lambda e: self.clear_btn.config(
            bg=self.colors['bg_button'],
            fg=self.colors['text_primary']
        ))
        
        # ========== STATUS E CRÉDITOS NA MESMA LINHA ==========
        status_credits_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        status_credits_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Status label (centralizado)
        self.status_label = tk.Label(
            status_credits_frame,
            text=self.lang.get_text('status_ready'),
            fg=self.colors['success'],
            bg=self.colors['bg_primary'],
            font=("Consolas", 9, "bold")
        )
        self.status_label.pack(expand=True)
        
        # Área de texto
        result_frame = tk.Frame(self.root, bg=self.colors['bg_primary'])
        result_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            width=120,
            height=35,
            font=("Consolas", 9),
            wrap=tk.WORD,
            state='disabled',
            bg='#000000',
            fg='#00ff00',
            insertbackground='#00ff00',
            selectbackground='#003300',
            relief="flat"
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Configura as tags de texto
        self.setup_text_tags()
        
        # Mensagem de boas-vindas inicial
        self.show_welcome_message()
    
    def on_language_change(self, display_name, language_code):
        """Atualiza o idioma quando o usuário seleciona um novo"""
        self.language_var.set(display_name)
        if self.lang.set_language(language_code):
            self.update_interface_texts()
            self.refresh_console_content()
    
    def refresh_console_content(self):
        """Atualiza todo o conteúdo do console para o novo idioma"""
        current_content = self.result_text.get(1.0, tk.END)
        
        # Se for apenas a mensagem de boas-vindas, recarrega completamente
        if "WinLogZ" in current_content or "Windows Log Analyzer v1.0" in current_content:
            self.show_welcome_message()
        # Se tiver conteúdo de análise, tenta traduzir as partes fixas
        elif ">>>" in current_content or "===" in current_content:
            self.translate_existing_content(current_content)
    
    def translate_existing_content(self, content):
        """Tenta traduzir o conteúdo existente do console"""
        # Limpa o console
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        
        # Divide o conteúdo em linhas
        lines = content.split('\n')
        
        for line in lines:
            if not line.strip():
                self.result_text.insert(tk.END, "\n")
                continue
                
            # Tenta identificar e traduzir padrões conhecidos
            translated_line = self.translate_line(line)
            self.result_text.insert(tk.END, translated_line + "\n")
        
        self.result_text.config(state='disabled')
        self.result_text.see(tk.END)
    
    def translate_line(self, line):
        """Traduz uma linha individual baseada em padrões"""
        # Padrões de tradução
        patterns = {
            '>>> INITIATING SECURITY SCAN PROTOCOL': 'analysis_starting',
            '>>> INICIANDO PROTOCOLO DE VARREdura DE SEGURANÇA': 'analysis_starting',
            '>>> INICIANDO PROTOCOLO DE ESCANEO DE SEGURIDAD': 'analysis_starting',
            
            '[CONFIG] False positive filters: ENABLED': 'config_filters_enabled',
            '[CONFIG] Filtros de falsos positivos: ATIVADOS': 'config_filters_enabled',
            '[CONFIG] Filtros de falsos positivos: ACTIVADOS': 'config_filters_enabled',
            
            '[CONFIG] False positive filters: DISABLED': 'config_filters_disabled',
            '[CONFIG] Filtros de falsos positivos: DESATIVADOS': 'config_filters_disabled',
            '[CONFIG] Filtros de falsos positivos: DESACTIVADOS': 'config_filters_disabled',
            
            '>>> SCAN RESULTS SUMMARY': 'results_summary',
            '>>> RESUMO DOS RESULTADOS': 'results_summary',
            '>>> RESUMEN DE RESULTADOS DEL ESCANEO': 'results_summary',
            
            '[MODE] False positive filters: ACTIVE': 'results_mode_active',
            '[MODO] Filtros de falsos positivos: ATIVO': 'results_mode_active',
            '[MODO] Filtros de falsos positivos: ACTIVO': 'results_mode_active',
            
            '>>> THREAT DETAILS': 'results_threat_details',
            '>>> DETALHES DAS AMEAÇAS': 'results_threat_details',
            '>>> DETALLES DE AMENAZAS': 'results_threat_details',
            
            '>>> SECURITY SCAN COMPLETE': 'results_complete',
            '>>> VARREDURA DE SEGURANÇA CONCLUÍDA': 'results_complete',
            '>>> ESCANEO DE SEGURIDAD COMPLETADO': 'results_complete',
            
            'Ready for next command...': 'results_ready',
            'Pronto para o próximo comando...': 'results_ready',
            'Listo para el siguiente comando...': 'results_ready',
            
            '>>> CONSOLE CLEARED': 'console_cleared',
            '>>> CONSOLE LIMPO': 'console_cleared',
            '>>> CONSOLA LIMPIADA': 'console_cleared',
        }
        
        # Verifica se a linha corresponde a algum padrão
        for pattern, translation_key in patterns.items():
            if pattern in line:
                return self.lang.get_text(translation_key)
        
        # Se não encontrou padrão, retorna a linha original
        return line
    
    def update_interface_texts(self):
        """Atualiza todos os textos da interface para o idioma selecionado"""
        # Atualiza o título
        self.title_label.config(text=self.lang.get_text('title'))
        
        # Atualiza o checkbox de filtros
        if self.enable_filters.get():
            self.filter_checkbox.config(text=self.lang.get_text('filter_checkbox'))
            self.filter_status.config(text=self.lang.get_text('filter_active'))
        else:
            checkbox_text = self.lang.get_text('filter_checkbox').replace('[X]', '[ ]')
            self.filter_checkbox.config(text=checkbox_text)
            self.filter_status.config(text=self.lang.get_text('filter_disabled'))
        
        # Atualiza os botões
        self.analyze_btn.config(text=self.lang.get_text('analyze_button'))
        self.report_btn.config(text=self.lang.get_text('report_button'))
        self.clear_btn.config(text=self.lang.get_text('clear_button'))
        
        # Atualiza o crédito
        self.credits_label.config(text=self.lang.get_text('developed_by'))
        
        # Atualiza o status
        current_status = self.status_label.cget('text')
        if any(word in current_status for word in ['PRONTO', 'READY', 'LISTO']):
            self.status_label.config(text=self.lang.get_text('status_ready'))
        elif any(word in current_status for word in ['ANALISANDO', 'ANALYZING', 'ANALIZANDO']):
            self.status_label.config(text=self.lang.get_text('status_analyzing'))
    
    def setup_text_tags(self):
        """Configura as tags de texto para cores"""
        tags_config = {
            "severity_high": {'foreground': '#ff0000', 'font': ("Consolas", 9, "bold")},
            "severity_medium": {'foreground': '#ffff00', 'font': ("Consolas", 9, "bold")},
            "severity_low": {'foreground': '#00ff00', 'font': ("Consolas", 9)},
            "alert": {'foreground': '#ff0000', 'font': ("Consolas", 9, "bold")},
            "success": {'foreground': '#00ff00', 'font': ("Consolas", 9, "bold")},
            "warning": {'foreground': '#ffff00', 'font': ("Consolas", 9, "bold")},
            "header": {'foreground': '#00ff88', 'font': ("Consolas", 10, "bold")},
            "log": {'foreground': '#00cc00'},
        }
        
        for tag, config in tags_config.items():
            self.result_text.tag_config(tag, **config)
    
    def show_welcome_message(self):
        """Exibe mensagem de boas-vindas no idioma selecionado"""
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        
        # Verifica os privilégios reais
        admin_privileges = is_admin()
        
        welcome_msg = [
            "=" * 70,
            self.lang.get_text('welcome_title'),
            self.lang.get_text('welcome_version'),
            "=" * 70,
            "",
            self.lang.get_text('welcome_initializing'),
            self.lang.get_text('welcome_access'),
        ]
        
        # Adiciona mensagem de privilégios baseada na verificação real
        if admin_privileges:
            welcome_msg.append(self.lang.get_text('welcome_privilege'))
            welcome_msg.append("[SUCCESS] Running with administrator privileges")
        else:
            welcome_msg.append("[WARNING] Running WITHOUT administrator privileges")
            welcome_msg.append("[ALERT] Some logs may not be accessible")
        
        welcome_msg.extend([

            "",
            self.lang.get_text('welcome_commands'),
            self.lang.get_text('welcome_analyze_desc'),
            self.lang.get_text('welcome_report_desc'),
            self.lang.get_text('welcome_clear_desc'),

            ""
        ])
        
        for line in welcome_msg:
            if ">>>" in line or "===" in line:
                self.result_text.insert(tk.END, line + "\n", "header")
            elif "[GRANTED]" in line or "[SUCCESS]" in line or "[ADMINISTRATOR]" in line or "[PERMITIDO]" in line:
                self.result_text.insert(tk.END, line + "\n", "success")
            elif "[ADMINISTRADOR]" in line or "[CONCEDIDO]" in line:
                self.result_text.insert(tk.END, line + "\n", "success")
            elif "[WARNING]" in line or "[ALERT]" in line:
                self.result_text.insert(tk.END, line + "\n", "warning")
            else:
                self.result_text.insert(tk.END, line + "\n", "log")
        
        self.result_text.config(state='disabled')
    
    def on_filter_toggle(self):
        """Atualiza o status dos filtros"""
        if self.enable_filters.get():
            self.filter_status.config(text=self.lang.get_text('filter_active'), fg=self.colors['success'])
            self.filter_checkbox.config(text=self.lang.get_text('filter_checkbox'))
        else:
            self.filter_status.config(text=self.lang.get_text('filter_disabled'), fg=self.colors['error'])
            # Substitui [X] por [ ] quando desativado
            checkbox_text = self.lang.get_text('filter_checkbox').replace('[X]', '[ ]')
            self.filter_checkbox.config(text=checkbox_text)
    
    def log_message(self, message):
        """Adiciona mensagem à área de texto"""
        self.result_text.config(state='normal')
        
        # Determina a tag baseada no conteúdo
        if any(word in message for word in ["ERROR", "ERRO", "FAILED", "FALHA"]):
            tag = "alert"
        elif any(word in message for word in ["SUCCESS", "SUCESSO", "COMPLETE", "COMPLETO", "READY", "PRONTO"]):
            tag = "success"
        elif any(word in message for word in ["WARNING", "ALERTA", "SUSPICIOUS", "SUSPEIT"]):
            tag = "warning"
        elif message.startswith(">>>") or message.startswith("==="):
            tag = "header"
        else:
            tag = "log"
        
        self.result_text.insert(tk.END, message + "\n", tag)
        self.result_text.config(state='disabled')
        self.result_text.see(tk.END)
        self.root.update()
    
    def start_analysis(self):
        """Inicia a análise de logs"""
        # Verifica privilégios antes de iniciar análise
        if not is_admin():
            response = messagebox.askyesno(
                "Privilégios de Administrador", 
                "O programa não está sendo executado como administrador.\n"
                "Alguns logs podem não estar acessíveis.\n\n"
                "Deseja continuar mesmo assim?"
            )
            if not response:
                return
        
        if LogAnalyzer is None:
            self.log_message("ERROR: LogAnalyzer not available")
            return
        
        self.analyze_btn.config(state='disabled')
        self.status_label.config(text=self.lang.get_text('status_analyzing'), fg=self.colors['warning'])
        
        # Limpa a área de texto
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        
        self.log_message(self.lang.get_text('analysis_starting'))
        self.log_message("=" * 50)
        
        # Mostra a configuração
        if self.enable_filters.get():
            self.log_message(self.lang.get_text('config_filters_enabled'))
            self.log_message(self.lang.get_text('config_system_events'))
        else:
            self.log_message(self.lang.get_text('config_filters_disabled'))
            self.log_message(self.lang.get_text('config_showing_all'))
        
        # Executa em thread separada
        thread = threading.Thread(target=self.analyze_logs_thread)
        thread.daemon = True
        thread.start()
    
    def analyze_logs_thread(self):
        """Thread para análise de logs"""
        try:
            self.analyzer = LogAnalyzer(
                log_callback=self.log_message,
                enable_filters=self.enable_filters.get(),
                language_manager=self.lang
            )
            findings = self.analyzer.comprehensive_analysis()
            self.root.after(0, self.analysis_complete, findings)
        except Exception as e:
            self.root.after(0, self.analysis_error, str(e))
    
    def analysis_complete(self, findings):
        """Chamado quando a análise é completada"""
        self.analyze_btn.config(state='normal')
        
        self.log_message("=" * 50)
        
        if findings:
            self.status_label.config(
                text=self.lang.get_text('status_complete', len(findings)), 
                fg=self.colors['success']
            )
            
            self.log_message(self.lang.get_text('results_summary'))
            self.log_message("-" * 40)
            
            # Mostra a configuração usada
            if self.enable_filters.get():
                self.log_message(self.lang.get_text('results_mode_active'))
            else:
                self.log_message(self.lang.get_text('results_mode_inactive'))
                
            self.log_message(self.lang.get_text('results_total', len(findings)))
            
            # Conta por severidade/graus de ameaças
            high_sev = sum(1 for f in findings if f.get('Severidade') == 'High')
            medium_sev = sum(1 for f in findings if f.get('Severidade') == 'Medium')
            low_sev = sum(1 for f in findings if f.get('Severidade') == 'Low')
            
            self.log_message(self.lang.get_text('results_high', high_sev), "severity_high")
            self.log_message(self.lang.get_text('results_medium', medium_sev), "severity_medium")
            self.log_message(self.lang.get_text('results_low', low_sev), "severity_low")
            
            self.log_message("-" * 40)
            self.log_message(self.lang.get_text('results_threat_details'))
            
            for i, finding in enumerate(findings, 1):
                severity = finding.get('Severidade', 'Medium')
                severity_tag = f"severity_{severity.lower()}"
                
                self.log_message(self.lang.get_text('results_threat', i, severity.upper()))
                self.log_message(self.lang.get_text('results_type', finding['Tipo']))
                self.log_message(self.lang.get_text('results_eventid', finding['EventID']))
                self.log_message(self.lang.get_text('results_time', finding['Horário']))
                self.log_message(self.lang.get_text('results_description', finding.get('Descrição', 'N/A')))
                
                # Detalhes
                details = finding['Detalhes']
                if isinstance(details, list) and details:
                    self.log_message(self.lang.get_text('results_details'))
                    for j, detail in enumerate(details[:4]):
                        if detail:
                            self.log_message(f"  {j+1}. {detail}")
                    if len(details) > 4:
                        self.log_message(f"  ... and {len(details) - 4} more items")
                else:
                    self.log_message(f"{self.lang.get_text('results_details')} {details}")
                
        else:
            self.status_label.config(
                text=self.lang.get_text('status_complete_clean'), 
                fg=self.colors['success']
            )
            self.log_message(self.lang.get_text('results_clean'))
            
            if self.enable_filters.get():
                self.log_message(self.lang.get_text('results_no_threats'))
                self.log_message(self.lang.get_text('results_filters_working'))
            else:
                self.log_message(self.lang.get_text('results_no_threats'))
                self.log_message(self.lang.get_text('results_secure'))
        
        self.log_message("=" * 50)
        self.log_message(self.lang.get_text('results_complete'))
        self.log_message(self.lang.get_text('results_ready'))
    
    def analysis_error(self, error_msg):
        """Chamado quando ocorre um erro na análise"""
        self.analyze_btn.config(state='normal')
        self.status_label.config(text=self.lang.get_text('status_error'), fg=self.colors['error'])
        self.log_message(self.lang.get_text('error_system'))
        self.log_message(self.lang.get_text('error_message', error_msg), "alert")
        self.log_message(self.lang.get_text('error_permissions'))
        messagebox.showerror("Analysis Error", f"Failed to analyze logs:\n{error_msg}")
    
    def generate_report(self):
        """Gera relatório"""
        try:
            self.result_text.config(state='normal')
            content = self.result_text.get(1.0, tk.END)
            self.result_text.config(state='disabled')
            
            if len(content.strip()) > 50:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"security_report_{timestamp}.txt"
                
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("WinLogZ - SECURITY ANALYSIS REPORT\n")
                    f.write("=" * 50 + "\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(content)
                
                self.log_message(self.lang.get_text('report_generated'))
                self.log_message(self.lang.get_text('report_file', filename))
                self.log_message(self.lang.get_text('report_location', os.path.abspath(filename)))
                
                messagebox.showinfo(
                    self.lang.get_text('report_saved'), 
                    f"Report saved as:\n{filename}"
                )
            else:
                messagebox.showwarning("No Data", "No analysis data to report")
                
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report:\n{str(e)}")
    
    def clear_results(self):
        """Limpa a área de resultados"""
        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        
        self.status_label.config(text=self.lang.get_text('status_ready'), fg=self.colors['success'])
        
        # Mostra a mensagem de console limpo
        self.result_text.config(state='normal')
        self.log_message(self.lang.get_text('console_cleared'))
        self.log_message(self.lang.get_text('console_ready'))
        self.log_message(self.lang.get_text('console_continue'))
    
    def run(self):
        """Inicia a aplicação"""
        self.root.mainloop()


# Garante que a classe Winlogz está definida
if __name__ == "__main__":
    app = Winlogz()
    app.run()
![project_logo](assets/winlogzanalysis.png)

## <img width="20" height="200" src="https://img.icons8.com/color/48/windows-10.png" alt="windows-10"/> WinLogZ - Windows Logs Analyzer v1.0🔍

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Windows](https://img.shields.io/badge/Platform-Windows-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Uma ferramenta avançada de análise de logs do Windows para monitoramento de segurança, desenvolvida em Python com interface estilo Terminal Linux/Matrix.

## 📋 Índice

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Tecnologias](#tecnologias)
- [Contribuição](#contribuição)
- [Licença](#licença)

## 🎯 Visão Geral

O **WinLogZ** é uma aplicação desktop especializada na análise de logs de segurança do Windows. Detecta atividades suspeitas como tentativas de força bruta, escalação de privilégios e acesso não autorizado. Foi inspirado no CrowdSec para distribuições linux e usa interface estilo terminal linux/matrix.

## ✨ Funcionalidades

### 🔍 Análise Avançada de Logs
- **Varredura Completa**: Análise detalhada dos logs de segurança do Windows
- **Detecção de Força Bruta**: Identificação inteligente de padrões de ataque
- **Monitoramento de Privilégios**: Alerta sobre escalação de permissões suspeitas
- **Filtros Configuráveis**: Sistema inteligente para reduzir falsos positivos. Você mesmo pode configurar seus próprios filtros no config.py e os filtros que configurei, são filtros padrão de rede levando em consideração o funcionamento do sistema operacional Windows 11.

### 🌐 Suporte Multi-idioma
- **Português, Inglês e Espanhol**: Interface completamente traduzida
- **Troca Dinâmica**: Alteração de idioma em tempo real
- **Localização Contextual**: Mensagens adaptadas a cada cenário

### 📊 Sistema de Relatórios
- **Exportação Detalhada**: Geração de relatórios completos em texto
- **Logs em Tempo Real**: Visualização imediata durante a análise
- **Timestamps Automáticos**: Registro temporal em todos os eventos

### 🎨 Interface Matrix
- **Tema Verde/Preto**: Design inspirado no filme Matrix
- **Console Interativo**: Terminal estilo hacking/Matrix
- **Navegação Intuitiva**: Controles simplificados e eficientes

## 🚀 Instalação

### Pré-requisitos
- Windows 10/11 ou Windows Server 2016+
- Python 3.8 ou superior
- Permissões de administrador para acesso completo aos logs

### 📦 Método 1: Executável (Recomendado)
1. Baixe o `WinLogZ.exe` mais recente
2. Execute como administrador (botão direito → "Executar como administrador")
3. A ferramenta está pronta para uso!

### 🔧 Método 2: Código Fonte

```bash
# Clone o repositório
git clone https://gitlab.com/PHDevSec/winanalysis.git
cd winanalysis

# Instale as dependências
pip install -r requirements.txt

# Execute a aplicação
python main.py

```
## 🎮 Como Usar

### 🖥️ Primeiros Passos

- Inicie o WinLogZ como administrador
- Selecione o Idioma no menu superior central
- Configure os Filtros conforme sua necessidade
- Clique em "Iniciar Análise de Logs"

### 🔍 Realizando Análises

- Modo Rápido (com filtros)
- Ative os filtros de falsos positivos
- Clique em "INICIAR ANÁLISE DE LOGS"
- Revise as ameaças detectadas

### Modo Detalhado (sem filtros)

- Desative os filtros para análise completa
- Execute a análise para ver todos os eventos
- Analise o relatório completo

### ⚙️ Configurações Avançadas

- Filtros Ativos: Ideal para monitoramento diário
- Filtros Inativos: Perfeito para auditorias completas
- Idioma Dinâmico: Alterável a qualquer momento

### 💾 Exportando Dados

- Após análise, clique em "GERAR RELATÓRIO"
- Arquivo salvo como security_report_AAAAMMDD_HHMMSS.txt
- Localize no diretório da aplicação

# 📁 Estrutura do Projeto

```bash
wianalysis: # Repositório
    WinLogZ/ # Diretório Principal
        ├── dist/                  # Diretório onde está o executável (exe)
        ├──     ├── WinLogZ.exe
        ├── assets/                # Recursos visuais
        ├──     ├── winlogzanalysis.png                
        ├── main.py                 # Ponto de entrada da aplicação
        ├── gui.py                  # Interface gráfica Matrix
        ├── log_analyzer.py         # Motor de análise de logs
        ├── language_manager.py     # Sistema de internacionalização
        ├── config.py              # Configurações e parâmetros
        ├── requirements.txt       # Dependências do projeto
        ├── README.md             # Documentação
```

## 🏗️ Arquitetura

- main.py: Orquestrador principal da aplicação
- gui.py: Interface visual com tema Matrix
- log_analyzer.py: Núcleo de análise de segurança
- language_manager.py: Gerenciador de multi-idioma
- config.py: Central de configurações
- WinLogZ.exe: Arquivo executável 

## 🛠️ Tecnologias

### 💻 Stack Tecnológica

- Python 3.8+: Linguagem core
- Tkinter: Framework de interface gráfica
- pywin32: Integração com API Windows
- pandas: Processamento de dados avançado

## 📚 Bibliotecas Principais

Python:

- pywin32==310      # Acesso nativo aos logs do Windows
- pandas==2.3.3     # Análise e manipulação de dados

## 🏛️ Arquitetura

- Padrão MVC: Separação clara de responsabilidades
- Interface Nativa: Performance otimizada para Windows
- Processamento Assíncrono: Análise sem travar a interface
- Sistema Modular: Fácil extensão e manutenção

## ⚡ Otimizações

- Feche aplicações pesadas durante a análise
- Use filtros para melhor performance
- Analise períodos específicos quando possível

## 🤝 Contribuição

Veja como ajudar:

- Faça um Fork do projeto
- Crie uma Branch:

bash
```bash
git checkout -b feature/sua-feature

```
Commit suas Mudanças:

bash
```bash
git commit -m 'Adiciona feature'

```

Push para a Branch:

bash

```bash
git push origin feature/sua-feature

```
- Abra um Pull Request

## 🎯 Áreas de Melhoria

- Novos detectores de ameaças
- Otimizações de performance
- Suporte a mais idiomas
- Melhorias na interface
- Análise mais avançada de logs

## 📝 Guidelines

- Siga o padrão PEP 8
- Documente o código
- Mantenha compatibilidade com Windows

## 📄 Licença

- Distribuído sob licença MIT.
- [MIT License](https://opensource.org/license/mit)
- Permissão gratuita a qualquer um obter uma cópia deste software e seus arquivos. Software Open Source.

[Copyright (c) 2025 João Pedro H](https://www.linkedin.com/in/jo%C3%A3o-pedro-h-1a8000345/).

## ⚖️ Isenção de Responsabilidade

### Este software é fornecido "como está", sem garantias de qualquer tipo. O uso em ambientes de produção é de sua inteira responsabilidade. Não me responsabilizo por uso indevido.

<div align="center">

#### ⭐ Se o WinLogZ foi útil para você, considere dar uma estrela no repositório! ⭐

🛡️🔒 "Conhece-te a ti mesmo" 🔒🛡️


</div>

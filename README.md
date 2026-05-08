# Mini-Blockchain Simétrica com Autenticação 2FA

Este projeto implementa uma mini-blockchain multiusuário com criptografia simétrica (AES-GCM), derivação de chaves (PBKDF2) e autenticação de dois fatores (TOTP).

# 1. Pré-requisitos e Instalação

*Python:* Versão *3.10 ou superior*.
*Dependências:* Instale as bibliotecas necessárias executando o comando:
  `pip install -r requirements.txt`

*Aviso para usuários de macOS:* O Python instalado via Homebrew não traz a biblioteca gráfica `Tkinter` por padrão. Para que a interface gráfica funcione, instale-o via terminal. Exemplo: `brew install python-tk@3.13` (ajuste para a sua versão do Python).

# 2. Passo a Passo de Execução

O sistema funciona em uma arquitetura de Cliente-Servidor. Você precisará de dois terminais abertos na raiz do projeto.

*Passo 1: Iniciar o Servidor*
No primeiro terminal, inicie a rede executando:
`python -m server.main`

*Passo 2: Iniciar o Cliente (Interface Gráfica)*
No segundo terminal, abra a interface visual executando:
`python -m client.gui`

# 3. Como Usar a Aplicação (Interface Gráfica)

A interação com a blockchain é feita inteiramente através da janela gráfica que será aberta:

1. *Cadastro de Usuário:* Faça o registro de um novo usuário. Uma tela de sucesso exibirá o seu *Segredo TOTP* (em base32).
2. *Configuração do 2FA:* Adicione o Segredo TOTP exibido no seu aplicativo autenticador de celular (ex: Google Authenticator) ou utilize o script auxiliar fornecido no projeto executando `python client/totp_helper.py` para gerar os códigos temporários no terminal.
3. *Login:* Acesse sua conta usando seu usuário, senha e o código de 6 dígitos gerado pelo TOTP.
4. *Adicionar Bloco:* Na aba correspondente, digite os dados arbitrários (mensagem, transação) e confirme para adicionar à blockchain.
5. *Listar Blockchain:* Visualize a cadeia de blocos. O sistema decifra e exibe o conteúdo apenas dos blocos criados por você (isolamento multiusuário).
6. *Ferramenta de Adulteração:* Use a aba de testes para manipular maliciosamente os dados (ciphertext ou prev_hash) e veja o servidor e o cliente rejeitarem a quebra de integridade.

# 4. Testes Automatizados

O sistema conta com 17 testes automatizados que validam desde o determinismo da derivação de chaves até a detecção de adulteração na blockchain. Para executá-los, rode:
`pytest -q tests/`

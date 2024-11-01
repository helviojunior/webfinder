# Web Finder (PT-BR)

Esta é uma ferramenta para busca de endereços IP que respondam por uma URL específica.

## Instalação

> :information_source: Recomendamos a utilização do `pipx` ao invés do `pip` para instalação no sistema.

```
python3 -m pipx install wafwebfinder
```

> :information_source: Verifique a necessidade de executar também o comando `python3 -m pipx ensurepath`

## Conceito técnico

Ao realizar uma requisição HTTP/S para um host a primeira fase a ser realizada pelo cliente é a resolução de nome para IP e posteriormente conexão direta para este IP. Este procedimento se refere até a camada de Transporte do modelo OSI (camada 4) onde temos apenas IP e porta. Após a conexão TCP ocorrer com sucesso o cliente monta um cabeçalho de requisição HTTP e envia ao servidor, veja o exemplo a seguir:

Supondo que em um navegador seja digitado https://www.helviojunior.com.br (conforme o comando curl abaixo), primeiramente o cliente resolverá o nome DNS para o IP (cujo resultado será 54.244.151.52) e posteriormente enviará o cabeçalho conforme abaixo:

```bash
curl -k https://www.helviojunior.com.br
```

Cabeçalho:
```
GET / HTTP/1.1
Host: www.helviojunior.com.br
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Te: trailers
Connection: close
```

Como podemos observar no cabeçalho `Host` temos o nome completo do servidor. Com o advento do HTTP 1.1 em diante o servidor leva em consideração este campo para rotear internamente em qual site deve responder, sendo que se o servidor estiver preparado para responder por este host (www.helviojunior.com.br) o mesmo o fará.

Porém, nós podemos realizar o mesmo processo de forma diferente, onde direcionamos o cliente em qual endereço IP o mesmo deve conectar e forçamos o host no cabeçalho do HTTP conforme o comando abaixo:

```bash
curl -k -H 'Host: www.helviojunior.com.br' https://54.244.151.52
```

Deste modo obrigatoriamente a conexão TCP ocorrerá para o IP 54.244.151.52 independente da resolução DNS, porém no cabeçalho http será enviado o host www.helviojunior.com.br. Desta forma iremos obter o mesmo resultado como resposta.

Deste modo podemos alterar o endereço IP para qualquer outro, como por exemplo 10.10.10.10 que de o servidor deste IP existir e tiver preparado para responder ao site www.helviojunior.com.br a resposta (HTTP Status code e tamanho) será a mesma.

```bash
curl -k -H 'Host: www.helviojunior.com.br' https://10.10.10.10
```

> :information_source: Porém, no cenário acima o `Subject Name` informado via `SNI` será o IP ao invés do `host`, sendo assim em cenários onde o TLS exige SNI o comando acima não irá funcionar, desta forma precisaremos utilizar outra estratégia.

Para isso utilizaremos o parâmetro `--resolve [DOMAIN]:[PORT]:[IP]` do CURL

```bash
curl -k --resolve www.helviojunior.com.br:443:54.244.151.52 https://www.helviojunior.com.br
```

Deste modo, igualmente no cenário anterior, obrigatoriamente a conexão TCP ocorrerá para o IP 54.244.151.52 pois o parâmetro `--resolve` ignora a resolução de nome via DNS. Adicionalmente desta forma o cabeçalho `host` e o `Subject Name` do `SNI` serão definidos corretamente.

Sendo assim podemos utilizar essa técnica para passar uma lista de IPs e verificar se eles estão configurados para responder por um determinado site.


## Utilização

Recomendamos a utilização dessa ferramenta seguindo os seguintes passos:
- Busca de todos os endereços IP atrelados ao cliente
- Criação de um arquivo TXT com todos os IPs
- Utilização do `WebFinder` para identificar em quais endereços IP o site é acessível

### Endereços IP

Supondo que em processo de enumeração encontrei para o cliente (dono do site helviojunior.com.br) os seguintes endereços IP:

```
13.77.161.179
104.215.148.63
40.76.4.15
54.244.151.52
172.217.1.99
```

### Executando o WebFinder

Ao executar o `WebFinder` temos o resultado abaixo, onde podemos observar que somente o servidor no IP 54.244.151.52 é capaz de responder pela URL www.helviojunior.com.br

```
#webfinder -t https://www.helviojunior.com.br/ -ip /tmp/ips.txt --check-both

       Web Finder v0.1.2 by Helvio Junior
       automated web server finder
       https://github.com/helviojunior/webfinder


 [+] Startup parameters
     command line: /usr/local/bin/webfinder -t https://www.helviojunior.com.br/ -ip /tmp/ips.txt --check-both
     target: https://www.helviojunior.com.br
     host: www.helviojunior.com.br
     tasks: 16
     request method: GET
     ip address list: /tmp/ips.txt
     start time 2021-06-16 10:31:16

 [+] Conectivity checker
 [+] Connection test againt https://www.helviojunior.com.br OK! (IP:54.244.151.52|CODE:200|SIZE:72826)

 [+] Scanning IP address for https://www.helviojunior.com.br
+ https://54.244.151.52 (CODE:200|SIZE:72826)
+ http://54.244.151.52 (CODE:200|SIZE:72826)

 [+] End time 2021-06-16 10:31:24
 [+] Finished tests against https://www.helviojunior.com.br, exiting
```

### Utilização com outras ferramentas

#### Enumeração DNS

Download da wordlist e script de recon DNS
```
git clone https://github.com/danielmiessler/SecLists
wget https://raw.githubusercontent.com/helviojunior/libs/master/python/enumdns.py
```

Enumeração
```
python3 enumdns.py -d helviojunior.com.br -w ./SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o dns_enum.txt
```

#### Filtrando endereços IP

Agora vamos extrair somente os endereços IPs (v4) únicos da enumeração do DNS

```
cat dns_enum.txt | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > ips.txt
```

#### Localizando servidores web

Utilize o `WebFinder` nos endereços IP listados para verificar quais detém a capacidade de responder pelo site desejado

```
webfinder -t https://www.helviojunior.com.br/ -ip ips.txt --check-both
```
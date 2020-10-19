## ELK Stack (Filelogs -> Beats -> Logstash -> ElasticSeach -> Kibana.)
[![Banner](banner.png)]()  
##### Configure uma pilha ELK para sua central de SIEM, monitoramento de logs e muito mais ! 

# Criando ambiente para instalação com multipass:
> O objetivo desta seção é utilizar o snap para instalar o multipass para que possamos obter uma vm ubuntu rapida e facil para implantar o ```ELK stack```.  

## Instalando o Snap e Multipass:  
```
$ apt-get update
$ apt-get install snapd
$ sudo snap install multipass
$ sudo ln /snap/bin/multipass /usr/bin/multipass
$ sudo multipass --help
```

## Criando VM ubuntu com Multipass:  
```
$ sudo multipass launch --name ELKSTACK --disk 20G --mem 4G
$ sudo multipass list
$ sudo multipass info ELKSTACK
$ sudo multipass shell ELKSTACK
```

### Instale o oracle java:   
```
$ sudo apt-get update
$ sudo apt-get install -y default-jre
$ java --version
```  

## Instalando e configurando certificado SSL:  
```
Crie os diretorios para os certificados:
$ sudo mkdir -p /etc/pki/tls/certs
$ sudo mkdir /etc/pki/tls/private

Pegue o ip da maquina: 
$ ip a s

Edite a linha "[ v3_ca ]" do arquivo openssl.cnf adicionaod o subjectAltNAME : 
$ sudo vi /etc/ssl/openssl.cnf
[ v3_ca ]
subjectAltName = IP: IP-DA-MAQUINA-AQUI

Gere o certificado:
$ cd /etc/pki/tls
$ sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:4096 -keyout private/elk.key -out certs/elk.crt
```

## Configurando ELKstack:  
### Elasticsearch ,Kibana, Logstash e Filebeats:  

##### ELASTICSEARCH  
```
$ wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.9.2-amd64.deb
$ sudo dpkg -i elasticsearch-7.9.2-amd64.deb
$ sudo service elasticsearch restart

Descomente e edite as linhas:
$ sudo vi /etc/elasticsearch/elasticsearch.yml
network.host: localhost
http.port: 9200
```

```
$ sudo service elasticsearch restart
$ sudo systemctl enable elasticsearch
$ sudo service elasticsearch status
```

##### KIBANA  
```
$ wget https://artifacts.elastic.co/downloads/kibana/kibana-7.9.2-amd64.deb
$ sudo dpkg -i kibana-7.9.2-amd64.deb

Descomente a linha:
$ sudo vi /etc/kibana/kibana.yml
server.host: "localhost"
```

```
$ sudo service kibana restart
$ sudo systemctl enable kibana
$ sudo service kibana status
```  

## Instalando Nginx:  
> O objetivo da instalação do nginx é utiliza-lo como um proxy para autenticação e proteção basica para o acesso ao kibana.  
```  
$ sudo apt-get install -y nginx apache2-utils
```  
#### Crie uma conta de usuario no proxy:  
```
$ sudo htpasswd -c /etc/nginx/htpasswd.users ELKSTACK
$ sudo truncate -s 0 /etc/nginx/sites-available/default
```  
#### Configurando arquivo defaults:  
```
$ sudo nano /etc/nginx/sites-available/default


server {
        listen 80 default_server; # Escutando na porta 80
        server_name 192.168.2.85; # Colocar o IP do servidor
        return         301 https://$server_name$request_uri; # Redireciona para porta 443/SSL
   }
 
    server {
        listen 443 default ssl; # Escutando na porta 443/SSL
 
        # Certificado SSL, Chave e Configurações
        ssl_certificate /etc/pki/tls/certs/elk.crt;
        ssl_certificate_key /etc/pki/tls/private/elk.key;
        ssl_session_cache shared:SSL:10m;
 
        # Autenticação básica usando a conta criada com htpasswd
        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;
 
        location / {
	 # Configurações de Proxy apontando para a instância do Kibana 
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }
    }

```   

```
$ sudo service nginx restart
$ sudo systemctl enable nginx
$ sudo service nginx status
```   

##### LOGSTASH:  
```
$ wget https://artifacts.elastic.co/downloads/logstash/logstash-7.9.2.deb
$ sudo dpkg -i logstash-7.9.2.deb
```

#### pipeline.conf:  
```
$ sudo nano /etc/logstash/conf.d/pipeline.conf
```

```
input {
  beats {
    port => 5044
  }
}

filter {
    grok { match => { "message" => "%{COMBINEDAPACHELOG}" } }

    mutate{ 
        convert => { "bytes" => "integer" } 
        convert => { "port" => "integer" } 
        convert => { "timetaken" => "integer" } 
        convert => { "subresponse" => "integer" } 
          }

    date { 
        match => [ "timestamp" , "YYYY-MM-dd HH:mm:ss" ] 
        timezone => "Etc/GMT"

         }

    geoip {
        source => "clientip"    
        target => "geoip"
          }
 
    useragent {
          source => "agent"
          target => "useragent"

              }
}

output {
  elasticsearch {
    hosts => "localhost:9200"
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM}"
    document_type => "%{[@metadata][type]}"
  }
}

``` 

``` 
$ sudo service logstash restart
$ sudo systemctl enable logstash
$ sudo service logstash status
``` 

##### FILEBEATS:
> Instale o filebeats nas maquinas que voce deseja monitorar.  
[Download BEATS](https://www.elastic.co/downloads/beats/filebeat "Clique aqui para efetuar o donwload do filebeats")  

```
$ wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.9.2-amd64.deb
$ sudo dpkg -i filebeat-7.9.2-amd64.deb
$ sudo mv /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.BKP
$ sudo nano /etc/filebeat/filebeat.yml
```

#### filebeat.yml  
> Obs: no campo "output.logstash" altere o endereço localhost para o ip do logstash.
```
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/apache2/*.log
    
filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: false


setup.template.settings:
  index.number_of_shards: 1


output.logstash:
  hosts: ["localhost:5044"]
  

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
 
```

##### Ative o module apache do filebeat:
```
$ sudo filebeat modules enable apache
```

``` 
$ sudo service filebeat restart
$ sudo systemctl enable filebeat
$ sudo service filebeat status
``` 

#### Acesse http://IP-ELK-SERVER
> Discover >> Create index pattern >> Index pattern name = filebeat-2020.xx >> Next step >> Time field = @timestamp >> Create index pattern. Return Discover. 


#### Logs de Vhots:
> Para logs personalizados ou vhosts voce precisa configurar os arquivos:
##### /etc/filebeat/filebeat.yml altere a "paths:" para o caminho dos logs do vhost como por exemplo:
```
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/www/meusite.com.br/logs/*.log
```

##### /etc/filebeat/modules.d/apache.yml adicione "var.paths:" para o caminho dos logs do vhost como por exemplo:
```
- module: apache
  # Access logs
  access:
    enabled: true
    var.paths: ["/var/www/meusite.com.br/logs/access.log"]
```

##### Agora precisamos limpar os logs do filebeat:
```
$ sudo su
$ echo '' > /var/lib/filebeat/registry/filebeat/log.json && exit
$ sudo service filebeat restart
```
## Configurando Elk em nós separados:
> O objetivo desta sessão é instalar cada um dos programas que forma a pilha elk em servidores dedicados de forma segura.  
> Para isso configuramos alguns dos hosts para serem acessados por qualquer maquina na rede e depois restringimos o acesso com o iptables.  
> Esta configuração fará com que o ELK seja acessivel somente pelo proxy nginx com usuario e senha configurados no proxy.  

### Criando hosts com multipass:
```
sudo multipass launch --name ELK-elastic --disk 10G --mem 3G
sudo multipass launch --name ELK-kibana --disk 10G --mem 2G
sudo multipass launch --name ELK-logstash --disk 10G --mem 2G
sudo multipass launch --name ELK-nginx --disk 10G --mem 1G
sudo multipass list
```
### Para todos os hosts:
> Obs: Atualize e instale o java em todos os nós.
```
$ sudo apt update
$ sudo apt install default-jre -y
```
### Instalando iptables-persistent:
> Instale o iptables nos hosts do Elasticsearch e Kibana.
```
$ sudo apt install iptables-persistent -y
$ sudo systemctl enable netfilter-persistent
```
### Elasticsearch  
#### Libere o Elastisearch para qualquer host na rede alterando as linhas do arquivo:  
```
$ sudo vi /etc/elasticsearch/elasticsearch.yml
```
```
cluster.initial_master_nodes: node-1
network.host: 0.0.0.0
```
#### Bloqueando todos os acessos ao Elasticsearch:
```
$ sudo iptables -A INPUT -p tcp --destination-port 9200 -j DROP
```
#### Liberando acesso para o Kibana:
> Altere o ip 10.51.127.145 para o ip do servidor do kibana.
```
$ sudo iptables -I INPUT -p tcp --destination-port 9200 -s 10.51.127.145 -j ACCEPT
```
#### Liberando acesso para o Logstash:
> Altere o ip 10.51.127.152 para o ip do servidor do logstash.
```
$ sudo iptables -I INPUT -p tcp --destination-port 9200 -s 10.51.127.152 -j ACCEPT 
```
#### Salve as regras do firewall e reinicie o elasticsearch:  
```
$ sudo service netfilter-persistent save
$ sudo service elasticsearch restart
```
### Kibana  
#### Libere o Kibana para qualquer host na rede alterando as linhas do arquivo:
```
$ sudo vi /etc/kibana/kibana.yml
```
```
server.host: "0.0.0.0"

```
#### Bloqueando todos os acessos ao Kibana:
```
$ sudo iptables -A INPUT -p tcp --destination-port 5601 -j DROP
```
#### Liberando acesso para o nginx:
> Altere o ip 10.51.127.90 para o ip do servidor do nginx.  
```
$ sudo iptables -I INPUT -p tcp --destination-port 9200 -s 10.51.127.90 -j ACCEPT
```
#### Salve as regras de firewall e reinicie o kibana:  
```
$ sudo service netfilter-persistent save
$ sudo service kibana restart
```
### Logstash
> Altere o ip do elasticsearch no arquivo /etc/logstash/conf.d/pipeline.conf  

### Nginx
> Altere o proxy_pass no arquivo default:
```
$ sudo vi /etc/nginx/site-available/default
```
#### Altere para o ip do kibana:  
```
proxy_pass http://10.51.127.145:5601;
```

## Arquivos de logs:
##### Se voce precisa de arquivos de logs para analisar e nao pode reproduzir um no momento, consulte meu projeto [fictitious.iocs](https://github.com/Outs1d3r-Net/fictitious.iocs "fictitious.iocs") se trata de um projeto com um log do apache que sofreu diversos tipos de ataques ciberneticos.

:brazil:

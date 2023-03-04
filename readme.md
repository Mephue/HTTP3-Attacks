# DE: HTTP/3-Angriffe

Basierend auf der Arbeit: "Sicherheitsanalyse von HTTP/3 mittels Threat Modeling" (Security Analysis of HTTP/3 using Threat Modeling)

Das Repository enthält Angriffsskripte, die erfolgreich angewendet wurden, um Schwachstellen in den Webservern nginx-quic und Caddy zu identifizieren. Die Skripte werden in diesem Repository sowohl für Lehrzwecke als auch für die Untersuchung weiterer Implementierungen bereitgestellt. Die Skripte basieren auf der Aioquic-Bibliothek und erweitern diese, um verschiedene Angriffe durchzuführen.  

## Installation

Für diese Angriffe wurde ein Debian 11 System verwendet. Die folgenden Anweisungen beziehen sich auf die Installation von aioquic unter Debian.

1. git clone https://github.com/aiortc/aioquic
2. sudo apt install libssl-dev python3-dev
3. cd aioquic
4. pip install -e .
5. pip install asgiref dnslib "flask<2.2" httpbin starlette "werkzeug<2.1" wsproto

## Angriffe durchführen

Es können drei verschiedene Angriffe mithilfe der Skripte durchgeführt werden.

- Angriff auf die Flusskontrolle
- Zustandsmanipulation
- Manipulation der Frame-Länge (Request Smuggling)

### Angriff auf die Flusskontrolle

Der Wert des Arguments --max-stream-data muss kleiner sein als die zu übertragenden Antwortdaten, damit der Angriff ausgeführt werden kann.

``` 
python3 http_attacks.py https://localhost:4433/ --max-stream-data 1024
``` 

In Wireshark kann festgestellt werden, ob zusätzliche DATA Frames gesendet wurden. Die Pakete sind mit TLS verschlüsselt und müssen vorher entschlüsselt werden. Dazu kann die Log-Funktion des Skripts aktiviert und in Wireshark eingebunden werden.

``` 
python3 http_attacks.py https://localhost:4433/ --max-stream-data 1024 -l keylogfile
``` 

### Zustandsmanipulation

Das Argument -t kann verwendet werden, um den Zustand einer Implementierung zu testen. Es gibt insgesamt fünf verschiedene Tests, die nacheinander ausgeführt werden können.

``` 
python3 http_attacks.py https://localhost:4433/ -t <1-5>
``` 

### Manipulation der Frame-Länge (Request Smuggling)

Das Argument --offset-test startet drei Tests mit unterschiedlichen Offsets für die Länge eines DATA Frames.

``` 
python3 flowcontrol_attack.py https://localhost:4433/ --offset-test
``` 


# EN: HTTP/3-Attacks

Based on the work: "Sicherheitsanalyse von HTTP/3 mittels Threat Modeling" (Security Analysis of HTTP/3 using Threat Modeling)

The repository contains attack scripts that have been successfully applied to identify vulnerabilities in the nginx-quic and Caddy web servers. The scripts are provided in this repository for educational purposes as well as investigation of further implementations. The scripts are based on the Aioquic library and extend it to perform various attacks.  


## Installation

A Debian 11 system was used to exploit these attacks. The following instructions refer to the installation of aioquic on Debian.

1. git clone https://github.com/aiortc/aioquic
2. sudo apt install libssl-dev python3-dev
3. cd aioquic
4. pip install -e .
5. pip install asgiref dnslib "flask<2.2" httpbin starlette "werkzeug<2.1" wsproto


## Performing Atacks

Three different attacks can be performed.

- Flow control attack
- State Manipulation
- Frame length manipulation (request smuggling)


### Flow control attack

The value of the --max-stream-data argument must be lower than the response data to be transmitted in order to execute the attack.

``` 
python3 http_attacks.py https://localhost:4433/ --max-stream-data 1024
``` 

In Wireshark, it can be determined whether additional DATA frames were sent. The packets are encrypted with TLS and must be decrypted beforehand. For this purpose, the log function of the script can be activated and included in Wireshark.

``` 
python3 http_attacks.py https://localhost:4433/ --max-stream-data 1024 -l keylogfile
``` 

### State Manipulation

The -t argument can be used to test the state of an implementation. There are a total of five different tests that can be executed one after the other.

``` 
python3 http_attacks.py https://localhost:4433/ -t <1-5>
``` 

### Frame length manipulation (request smuggling)

The --offset-test argument starts three tests with different offsets for the length of a DATA frame.

``` 
python3 flowcontrol_attack.py https://localhost:4433/ --offset-test
``` 
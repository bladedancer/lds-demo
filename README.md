# lds-demo

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -subj "/O=axway" -nodes -addext "keyUsage = digitalSignature, keyEncipherment, dataEncipherment, cRLSign, keyCertSign" -addext "extendedKeyUsage = serverAuth, clientAuth" -addext "subjectAltName = DNS:one.example.com,DNS:two.example.com" > /dev/null 2>&1


func-e run -c config/envoy.yaml


curl -vikn https://one.example.com:8443/one --resolve one.example.com:8443:127.0.0.1 -H "Accept: text/event-stream"

curl -vikn https://two.example.com:8443/two --resolve two.example.com:8443:127.0.0.1 -H "Accept: text/event-stream"

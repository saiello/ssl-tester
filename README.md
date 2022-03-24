## Overview


Java tool to test validity of client / server certificate pair used to setup mTLS. 


## Usage


Assemble the jar with maven

```bash
mvn clean package
```

Get the help
```
java -jar ssl-tester-1.0-SNAPSHOT-jar-with-dependencies.jar -help

usage: java -jar ssl-tester-1.0-SNAPSHOT-jar-with-dependencies.jar
 -ck,--clientKeystore <arg>                Client Keystore
 -ckp,--clientKeystorePassphrase <arg>     Client Keystore Passphrase
 -ct,--clientTruststore <arg>              Client Truststore
 -ctp,--clientTruststorePassphrase <arg>   Client Truststore Passphrase
 -debug                                    Enable ssl debug output
 -print                                    Enable logging
 -sk,--serverKeystore <arg>                Server Keystore
 -skp,--serverKeystorePassphrase <arg>     Server Keystore Passphrase
 -st,--serverTruststore <arg>              Server Truststore
 -stp,--serverTruststorePassphrase <arg>   Server Truststore Passphrase

```

Example command

```bash
java -jar target/ssl-tester-1.0-SNAPSHOT-jar-with-dependencies.jar  \
        --clientKeystore client-keystore.jks \
        --clientKeystorePassphrase changeit \
        --clientTruststore client-truststore.jks \
        --clientTruststorePassphrase changeit \
        --serverKeystore server-keystore.jks \
        --serverKeystorePassphrase chengeit \
        --serverTruststore server-truststore.jks \
        --serverTruststorePassphrase changeit        
```




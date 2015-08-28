# rdpsign
Remote Desktop Protocol (.rdp) file signing

https://github.com/nfedera/rdpsign


In Window Server 2008 Microsoft added the rdpsign.exe utility.
This command enables you to digitally sign a Remote Desktop Protocol(.rdp) file.
See https://technet.microsoft.com/en-us/library/cc753982.aspx for a detailed description.

To the best of my knowledge the specifications of the rdp signature creation are proprietary and have not been published until today (August 2015).

This python script is the result of reverse engineering the rdpsign.exe internals.


## Installation

    sudo curl https://raw.githubusercontent.com/nfedera/rdpsign/master/rdpsign.py -o /usr/local/bin/rdpsign
    sudo chmod a+rx /usr/local/bin/rdpsign


## Dependencies

- python 2.7 or later
- openssl commandline utility


## Usage

    rdpsign --help


## Demo (tested on Linux and Mac OSX)

First we create a simple openssl.conf file:

    [ req ]
    prompt = no
    distinguished_name = publisher
    x509_extensions = extensions

    [ publisher ]
    commonName = DEADBEEF

    [ extensions ]
    extendedKeyUsage = serverAuth

Now create a selfsigned test certificate and private key:

    openssl req -x509 -newkey rsa:2048 -nodes -out signer.crt -keyout signer.key -config openssl.conf
    openssl pkcs12 -export -passout pass: -in signer.crt -inkey signer.key -out signer.pfx

Sign your rdp file:

    rdpsign test.rdp test-signed.rdp signer.crt -k signer.key

Copy test-signed.rdp and signer.crt to your windows machine and import the signer.crt test certificate into your trusted root store:
- double click signer.crt
- click the "Install Certificate" button
- in the Certificate Import Wizard choose the "Trusted Root Certification Authorities" store


If you double click test-signed.rdp now you should get a dialog asking if you trust the DEADBEEF publisher.

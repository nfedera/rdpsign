# Remote Desktop Protocol (.rdp) File Signing Library
# Copyright (C) 2021 Cal Wing
# https://github.com/calw20/rdpsign2

# This library is a basic refactor of Norbert Federa's rdpsign program
#  https://github.com/nfedera/rdpsign
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import codecs, subprocess

from struct import pack
from base64 import b64encode

#List of rdp settings to sign
# A full list of RDP settings can be found over at 
#   https://www.donkz.nl/overview-rdp-file-settings/
SECURE_SETTINGS = (
    ( 'full address:s:', 'Full Address' ),
    ( 'alternate full address:s:', 'Alternate Full Address' ),
    ( 'pcb:s:', 'PCB' ),
    ( 'use redirection server name:i:', 'Use Redirection Server Name' ),
    ( 'server port:i:', 'Server Port' ),
    ( 'negotiate security layer:i:', 'Negotiate Security Layer' ),
    ( 'enablecredsspsupport:i:', 'EnableCredSspSupport' ),
    ( 'disableconnectionsharing:i:', 'DisableConnectionSharing' ),
    ( 'autoreconnection enabled:i:', 'AutoReconnection Enabled' ),
    ( 'gatewayhostname:s:', 'GatewayHostname' ),
    ( 'gatewayusagemethod:i:', 'GatewayUsageMethod' ),
    ( 'gatewayprofileusagemethod:i:', 'GatewayProfileUsageMethod' ),
    ( 'gatewaycredentialssource:i:', 'GatewayCredentialsSource' ),
    ( 'support url:s:', 'Support URL' ),
    ( 'promptcredentialonce:i:', 'PromptCredentialOnce' ),
    ( 'require pre-authentication:i:', 'Require pre-authentication' ),
    ( 'pre-authentication server address:s:', 'Pre-authentication server address' ),
    ( 'alternate shell:s:', 'Alternate Shell' ),
    ( 'shell working directory:s:', 'Shell Working Directory' ),
    ( 'remoteapplicationprogram:s:', 'RemoteApplicationProgram' ),
    ( 'remoteapplicationexpandworkingdir:s:', 'RemoteApplicationExpandWorkingdir' ),
    ( 'remoteapplicationmode:i:', 'RemoteApplicationMode' ),
    ( 'remoteapplicationguid:s:', 'RemoteApplicationGuid' ),
    ( 'remoteapplicationname:s:', 'RemoteApplicationName' ),
    ( 'remoteapplicationicon:s:', 'RemoteApplicationIcon' ),
    ( 'remoteapplicationfile:s:', 'RemoteApplicationFile' ),
    ( 'remoteapplicationfileextensions:s:', 'RemoteApplicationFileExtensions' ),
    ( 'remoteapplicationcmdline:s:', 'RemoteApplicationCmdLine' ),
    ( 'remoteapplicationexpandcmdline:s:', 'RemoteApplicationExpandCmdLine' ),
    ( 'prompt for credentials:i:', 'Prompt For Credentials' ),
    ( 'authentication level:i:', 'Authentication Level' ),
    ( 'audiomode:i:', 'AudioMode' ),
    ( 'redirectdrives:i:', 'RedirectDrives' ),
    ( 'redirectprinters:i:', 'RedirectPrinters' ),
    ( 'redirectcomports:i:', 'RedirectCOMPorts' ),
    ( 'redirectsmartcards:i:', 'RedirectSmartCards' ),
    ( 'redirectposdevices:i:', 'RedirectPOSDevices' ),
    ( 'redirectclipboard:i:', 'RedirectClipboard' ),
    ( 'devicestoredirect:s:', 'DevicesToRedirect' ),
    ( 'drivestoredirect:s:', 'DrivesToRedirect' ),
    ( 'loadbalanceinfo:s:', 'LoadBalanceInfo' ),
    ( 'redirectdirectx:i:', 'RedirectDirectX' ),
    ( 'rdgiskdcproxy:i:', 'RDGIsKDCProxy' ),
    ( 'kdcproxyname:s:', 'KDCProxyName' ),
    ( 'eventloguploadaddress:s:', 'EventLogUploadAddress' ),
)

#https://stackoverflow.com/a/312464
def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def validateRDP(rdpFile):
    rdpLines = [ f.strip() for f in rdpFile.splitlines(True) ]
    
    settings = []
    signlines = []
    signnames = []

    fulladdress = None
    alternatefulladdress = None

    #Generate the full list of settings
    for config in rdpLines:
        if config.startswith('full address:s:'):
            fulladdress = config[15:]
        elif config.startswith('alternate full address:s:'):
            alternatefulladdress = config[25:]
        elif config.startswith('signature:s:'):
            continue
        elif config.startswith('signscope:s:'):
            continue

        settings.append(config)

    #Prevent bypass attacks
    if fulladdress and not alternatefulladdress:
        settings.append('alternate full address:s:' + fulladdress)

    #Generate a list of settings to sign
    for s in SECURE_SETTINGS:
        for v in settings:
            if v.startswith(s[0]):
                signnames.append(s[1])
                signlines.append(v)
    
    return settings, signlines, signnames

def generateRDPSig(certfile, signlines, signnames, keyfile=None, splitSig=False):
    #[TODO] FIXME: check if signscope is not empty

    #Generate the message blob to sign & encode it correctly
    msgtext = '\r\n'.join(signlines) + '\r\n' + 'signscope:s:' + ','.join(signnames) + '\r\n' + '\x00'
    msgblob = msgtext.encode('UTF-16LE')

    params  = [ 'openssl', 'smime', '-sign', '-binary' ]
    params += [ '-signer', certfile ]
    params += [ '-outform', 'DER' ]
    params += [ '-noattr', '-nosmimecap' ]

    if keyfile is not None:
        params += [ '-inkey', keyfile ]

    try:
        proc = subprocess.Popen(
            params,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        opensslout, opensslerr = proc.communicate(msgblob)
    except OSError as e:
        sys.exit('Error calling OpenSSL command: ' + e.strerror)

    retcode = proc.poll()

    if retcode != 0:
        emsg = 'OpenSSL command failed (Return code #{0:d})'.format(retcode)
        if opensslerr is not None:
            emsg += ':\n'
            emsg += opensslerr.decode('utf-8')
        sys.exit(emsg)

    # for debugging:
    # with open('debug.msg', 'wb') as f:
    #	f.write(msgblob)
    # with open('debug.sig', 'wb') as f:
    #	f.write(opensslout)
    # run the following command to verify the signature
    # openssl cms -verify -inform DER -in debug.sig -content debug.msg -CAfile signer.pem


    # The Microsoft rdpsign.exe adds a 12 byte header to the signature 
    # before it gets base64 encoded
    # The meaning of the first 8 bytes is still unknown

    msgsig  = pack('<I', 0x00010001) # unknown DWORD value
    msgsig += pack('<I', 0x00000001) # unknown DWORD value
    msgsig += pack('<I', len(opensslout))
    msgsig += opensslout

    #Encode the signature, and if needed split it into 64 char chunks
    sigval = b64encode(msgsig).decode('ascii')
    sigval = "  ".join(chunks(sigval, 64))+"  " if splitSig else sigval

    return sigval

def signRDP(rdpFile, certfile, keyfile=None, splitSig=False):

    settings, signlines, signnames = validateRDP(rdpFile)
    fileSig = generateRDPSig(certfile, signlines, signnames, keyfile, splitSig)

    signedFile  = '\r\n'.join(settings)
    signedFile += '\r\n'
    signedFile += 'signscope:s:'
    signedFile += ','.join(signnames)
    signedFile += '\r\n'
    signedFile += 'signature:s:'
    signedFile += fileSig
    signedFile += '\r\n'
    
    return signedFile

if __name__ == "__main__":
    import sys, argparse
    #Argument Parser
    parser = argparse.ArgumentParser('rdpsign')
    parser.add_argument("infile", metavar='infile.rdp', help="RDP file to be signed")
    parser.add_argument("outfile", metavar='outfile.rdp', help="Signed rdp output file")
    parser.add_argument("certfile", metavar='signer.crt', help="Signing certificate")
    parser.add_argument("-k", dest='keyfile', metavar='signer.key', help="Specify private key file")
    parser.add_argument("-e", dest='encoding', metavar='encoding', default="utf-16", help="Encoding of input file (default is utf-16)")
    parser.add_argument("-s", dest="splitSig", action=argparse.BooleanOptionalAction, help="Split the generated signature string into 64 character chunks")

    args = parser.parse_args(sys.argv[1:])

    #Get the original RDP File to Sign
    try:
        with codecs.open(args.infile, 'r', encoding=args.encoding) as file:
            rdpFile = file.read()
    except Exception as e:
        sys.exit('Error reading rdp file: '+ str(e))

    #[TODO] fixme: check successful read, size of settings etc

    signedFile = signRDP(rdpFile, args.certfile, args.keyfile, args.splitSig)

    #Write the file to disk
    with codecs.open(args.outfile, mode='w', encoding='utf-16') as file:
        file.write(signedFile)


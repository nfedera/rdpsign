#!/usr/bin/env python

# Remote Desktop Protocol (.rdp) file signing
# Copyright (C) 2015 Norbert Federa
# https://github.com/nfedera/rdpsign
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


import sys
import argparse
import codecs
import subprocess

from struct import pack
from base64 import b64encode

def main(argv):
	securesettings = [
		[ 'full address:s:', 'Full Address' ],
		[ 'alternate full address:s:', 'Alternate Full Address' ],
		[ 'pcb:s:', 'PCB' ],
		[ 'use redirection server name:i:', 'Use Redirection Server Name' ],
		[ 'server port:i:', 'Server Port' ],
		[ 'negotiate security layer:i:', 'Negotiate Security Layer' ],
		[ 'enablecredsspsupport:i:', 'EnableCredSspSupport' ],
		[ 'disableconnectionsharing:i:', 'DisableConnectionSharing' ],
		[ 'autoreconnection enabled:i:', 'AutoReconnection Enabled' ],
		[ 'gatewayhostname:s:', 'GatewayHostname' ],
		[ 'gatewayusagemethod:i:', 'GatewayUsageMethod' ],
		[ 'gatewayprofileusagemethod:i:', 'GatewayProfileUsageMethod' ],
		[ 'gatewaycredentialssource:i:', 'GatewayCredentialsSource' ],
		[ 'support url:s:', 'Support URL' ],
		[ 'promptcredentialonce:i:', 'PromptCredentialOnce' ],
		[ 'require pre-authentication:i:', 'Require pre-authentication' ],
		[ 'pre-authentication server address:s:', 'Pre-authentication server address' ],
		[ 'alternate shell:s:', 'Alternate Shell' ],
		[ 'shell working directory:s:', 'Shell Working Directory' ],
		[ 'remoteapplicationprogram:s:', 'RemoteApplicationProgram' ],
		[ 'remoteapplicationexpandworkingdir:s:', 'RemoteApplicationExpandWorkingdir' ],
		[ 'remoteapplicationmode:i:', 'RemoteApplicationMode' ],
		[ 'remoteapplicationguid:s:', 'RemoteApplicationGuid' ],
		[ 'remoteapplicationname:s:', 'RemoteApplicationName' ],
		[ 'remoteapplicationicon:s:', 'RemoteApplicationIcon' ],
		[ 'remoteapplicationfile:s:', 'RemoteApplicationFile' ],
		[ 'remoteapplicationfileextensions:s:', 'RemoteApplicationFileExtensions' ],
		[ 'remoteapplicationcmdline:s:', 'RemoteApplicationCmdLine' ],
		[ 'remoteapplicationexpandcmdline:s:', 'RemoteApplicationExpandCmdLine' ],
		[ 'prompt for credentials:i:', 'Prompt For Credentials' ],
		[ 'authentication level:i:', 'Authentication Level' ],
		[ 'audiomode:i:', 'AudioMode' ],
		[ 'redirectdrives:i:', 'RedirectDrives' ],
		[ 'redirectprinters:i:', 'RedirectPrinters' ],
		[ 'redirectcomports:i:', 'RedirectCOMPorts' ],
		[ 'redirectsmartcards:i:', 'RedirectSmartCards' ],
		[ 'redirectposdevices:i:', 'RedirectPOSDevices' ],
		[ 'redirectclipboard:i:', 'RedirectClipboard' ],
		[ 'devicestoredirect:s:', 'DevicesToRedirect' ],
		[ 'drivestoredirect:s:', 'DrivesToRedirect' ],
		[ 'loadbalanceinfo:s:', 'LoadBalanceInfo' ],
		[ 'redirectdirectx:i:', 'RedirectDirectX' ],
		[ 'rdgiskdcproxy:i:', 'RDGIsKDCProxy' ],
		[ 'kdcproxyname:s:', 'KDCProxyName' ],
		[ 'eventloguploadaddress:s:', 'EventLogUploadAddress' ],
	]

	parser = argparse.ArgumentParser('rdpsign')
	parser.add_argument("infile", metavar='infile.rdp', help="rdp file to be signed")
	parser.add_argument("outfile", metavar='outfile.rdp', help="signed rdp output file")
	parser.add_argument("certfile", metavar='signer.crt', help="signing certificate")
	parser.add_argument("-k", dest='keyfile', metavar='signer.key', help="specify private key file")
	parser.add_argument("-e", dest='encoding', metavar='encoding', default="utf-16", help="encoding of input file (default is utf-16)")

	args = parser.parse_args(argv[1:])

	settings = list()
	signlines = list()
	signnames = list()

	try:
		with codecs.open(args.infile, 'r', encoding=args.encoding) as f:
			lines = [ v.strip() for v in f.readlines() ]
	except Exception as e:
		sys.exit('Error reading rdp file: '+ str(e))

	# fixme: check successful read, size of settings etc

	fulladdress = None
	alternatefulladdress = None

	for v in lines:
		if v.startswith('full address:s:'):
			fulladdress = v[15:]
		elif v.startswith('alternate full address:s:'):
			alternatefulladdress = v[25:]
		elif v.startswith('signature:s:'):
			continue
		elif v.startswith('signscope:s:'):
			continue
		settings.append(v)

	# prevent hacks via alternate full address

	if fulladdress and not alternatefulladdress:
		settings.append('alternate full address:s:' + fulladdress)

	for s in securesettings:
		for v in settings:
			if v.startswith(s[0]):
				signnames.append(s[1])
				signlines.append(v)

	#print signnames
	#print signlines

	#FIXME: check if signscope is not empty

	msgtext = '\r\n'.join(signlines) + '\r\n' + 'signscope:s:' + ','.join(signnames) + '\r\n' + '\x00'

	msgblob = msgtext.encode('UTF-16LE')

	params  = [ 'openssl', 'smime', '-sign', '-binary' ]
	params += [ '-signer', args.certfile ]
	params += [ '-outform', 'DER' ]
	params += [ '-noattr', '-nosmimecap' ]

	if args.keyfile is not None:
		params += [ '-inkey', args.keyfile ]

	try:
		proc = subprocess.Popen(
			params,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)

		opensslout, opensslerr = proc.communicate(msgblob)
	except OSError as e:
		sys.exit('Error calling openssl command: ' + e.strerror)

	retcode = proc.poll()

	if retcode is not 0:
		emsg = 'openssl command failed (return code #{0:d})'.format(retcode)
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

	sigval = b64encode(msgsig).decode('ascii')

	with codecs.open(args.outfile, mode='w', encoding='utf-16') as f:
		f.write('\r\n'.join(settings))
		f.write('\r\n')
		f.write('signscope:s:')
		f.write(','.join(signnames))
		f.write('\r\n')
		f.write('signature:s:')
		f.write(sigval)
		f.write('\r\n')

	pass


if __name__ == "__main__":
	main(sys.argv)


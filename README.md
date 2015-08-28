# rdpsign
Remote Desktop Protocol (.rdp) file signing

# rdpsign
Remote Desktop Protocol (.rdp) file signing

https://github.com/nfedera/rdpsign


In Window Server 2008 Microsoft added the rdpsign.exe utility.
This command enables you to digitally sign a Remote Desktop Protocol(.rdp) file.
See https://technet.microsoft.com/en-us/library/cc753982.aspx for a detailed description.

To the best of my knowledge the specifications of the rdp signature creation are proprietary and have not been published until today (August 2015).

This python script is the result of reverse engineering the rdpsign.exe internals.

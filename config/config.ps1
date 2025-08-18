


Write-Output " ______   ______   ___   __    ______   ________  _______        ______   ______     ____        "
Write-Output "/_____/\ /_____/\ /__/\ /__/\ /_____/\ /_______/\/______/\      /_____/\ /_____/\   /___/\       "
Write-Output "\:::__\/ \:::_ \ \\::\_\\  \ \\::::_\/_\__.::._\/\::::__\/__    \:::_ \ \\::::_\/_  \_::\ \      "
Write-Output " \:\ \  __\:\ \ \ \\:. `-\  \ \\:\/___/\  \::\ \  \:\ /____/\ ___\:(_) \ \\:\/___/\   \::\ \     "
Write-Output "  \:\ \/_/\\:\ \ \ \\:. _    \ \\:::._\/  _\::\ \__\:\\_  _\//__/\\: ___\/ \_::._\:\  _\: \ \__  "
Write-Output "   \:\_\ \ \\:\_\ \ \\. \`-\  \ \\:\ \   /__\::\__/\\:\_\ \ \\::\ \\ \ \     /____\:\/__\: \__/\ "
Write-Output "    \_____\/ \_____\/ \__\/ \__\/ \_\/   \________\/ \_____\/ \:_\/ \_\/     \_____\/\________\/ "
Write-Output "                                          \n\n                                                  "



if(!$args[0])
{
	Write-Output "Usage: config.ps1 192.168.1.1"
	exit
}
	
$server = $args[0]

if (!$(Test-Connection -BufferSize 32 -Count 1 -ComputerName $server -Quiet))
{
	Write-Host "Server Not Available" -ForegroundColor Red
	Write-Host "Did you start the server on Kali? (i.e. impacket-smbserver share . -smb2support)" -ForegroundColor Red
	exit
}

Write-Host "Server OK, starting to copy..." -ForegroundColor Green

############### START TASKS #################
mkdir temp -ErrorAction SilentlyContinue

# WINDBG
copy-item \\$server\share\winsdksetup.exe ./temp
Start-Process ./temp/winsdksetup.exe -Wait

copy-item \\$server\share\WinDBG_dark_theme.reg ./temp
reg import ./temp/WinDBG_dark_theme.reg

if ((!$(Test-Path -Path 'C:\Program Files\Windows Kits\10\Debuggers\x86')) -AND (!$(Test-Path -Path "C:\Program Files\Windows Kits\10\Debuggers\x86\winext"))) {
	Write-Host "C:\Program Files\Windows Kits\10\Debuggers\x86\winext NOT EXISTENT" -ForegroundColor Red
	exit
}

# Copying Files
copy-item \\$server\share\windbglib.py 'C:\Program Files\Windows Kits\10\Debuggers\x86'
copy-item \\$server\share\windbglib.pyc 'C:\Program Files\Windows Kits\10\Debuggers\x86'
copy-item \\$server\share\mona.py 'C:\Program Files\Windows Kits\10\Debuggers\x86'

copy-item \\$server\share\pykd2.pyd 'C:\Program Files\Windows Kits\10\Debuggers\x86\winext'
copy-item \\$server\share\pykd3.dll 'C:\Program Files\Windows Kits\10\Debuggers\x86\winext'
copy-item \\$server\share\narly.dll 'C:\Program Files\Windows Kits\10\Debuggers\x86\winext'

#Installing Python
copy-item \\$server\share\python-2.7.17.msi ./temp
Start-Process ./temp/python-2.7.17.msi -Wait

copy-item \\$server\share\python-3.8.0.exe ./temp
Start-Process ./temp/python-3.8.0.exe -Wait

copy-item \\$server\share\vcredist_x86.exe ./temp
Start-Process ./temp/vcredist_x86.exe -Wait


# Passing Tools
mkdir Tools
copy-item \\$server\share\code_caver.py ./Tools
copy-item \\$server\share\sysinternals.zip ./Tools


Write-Host "||||| All Done |||||" -ForegroundColor Green

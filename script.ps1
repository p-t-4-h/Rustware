# Nom de la bibliothèque kernel32.dll
$libraryName = "kernel32.dll"

# Signature de la fonction GetProcAddress
$signature = @"
    [DllImport("$libraryName", CharSet=CharSet.Auto)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
"@

# Charger la définition de la fonction GetProcAddress
Add-Type -MemberDefinition $signature -Name Win32GetProcAddress -Namespace Win32Functions

# Récupérer le handle de kernel32.dll
$kernel32Handle = [Win32Functions.Win32GetProcAddress]::GetProcAddress([IntPtr]::Zero, $libraryName)

if ($kernel32Handle -eq [IntPtr]::Zero) {
    Write-Host "Failed to get handle of $libraryName"
    exit
}

# Nom de la fonction à rechercher
$functionName = "CreateRemoteThreadEx"

# Obtenir l'adresse de la fonction CreateRemoteThreadEx
$functionAddress = [Win32Functions.Win32GetProcAddress]::GetProcAddress($kernel32Handle, $functionName)

if ($functionAddress -eq [IntPtr]::Zero) {
    Write-Host "Failed to get address of $functionName"
    exit
}

# Afficher l'adresse de la fonction CreateRemoteThreadEx
Write-Host ("Address of {0} in {1}: 0x{2}" -f $functionName, $libraryName, $functionAddress.ToString("X"))

# Définir la fonction pour récupérer le code et le message de la dernière erreur
function Get-LastError {
    # Appeler GetLastError pour obtenir le code d'erreur
    $lastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

    # Obtenir le message d'erreur en utilisant l'applet de commande PowerShell native
    $errorMessage = try { [System.ComponentModel.Win32Exception]::new($lastError) } catch { $null }

    if ($errorMessage) {
        $errorCode = $errorMessage.NativeErrorCode
        $errorDescription = $errorMessage.Message
        Write-Output "Numéro d'erreur : $errorCode"
        Write-Output "Message d'erreur : $errorDescription"
    } else {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Output "Numéro d'erreur : $errorCode"
        Write-Output "Message d'erreur : Impossible de récupérer le message d'erreur."
    }
}

# Appeler la fonction pour afficher le numéro et le message de la dernière erreur
Get-LastError

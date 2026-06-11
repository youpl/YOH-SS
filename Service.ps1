# ===============================================
# PowerShell Admin Check-Up + Réactivation (FIXED v2)
# ===============================================

# 1️⃣ Services à contrôler
$services = @(
    "SysMain", "PcaSvc", "DPS", "EventLog", "Schedule", 
    "Bam", "Dusmsvc", "Appinfo", "SSDPSRV", "CDPSvc", 
    "DcomLaunch", "PlugPlay"
)

# Stocke le rapport
$report = @()

foreach ($service in $services) {
    $s = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($s) {
        # Vérifie si le service est arrêté et le démarre
        if ($s.Status -ne "Running") {
            try {
                Set-Service -Name $service -StartupType Automatic
                Start-Service -Name $service
                $statusText = "Stopped → Started ✅"
                $color = "Green"
            } catch {
                $statusText = "Stopped → Failed ❌"
                $color = "Red"
            }
        } else {
            $statusText = "Running"
            $color = "Cyan"
        }
        $report += [PSCustomObject]@{
            Item = $service
            Type = "Service"
            Status = $statusText
            Color = $color
        }
    } else {
        $report += [PSCustomObject]@{
            Item = $service
            Type = "Service"
            Status = "Not Found ❌"
            Color = "Magenta"
        }
    }
}

# 2️⃣ Paramètres Windows (VÉRIFICATION UNIQUEMENT - pas de création)
$settings = @(
    @{ Name="CMD"; Path="HKCU:\Software\Policies\Microsoft\Windows\System"; Key="DisableCMD"; Safe="Available"; Warning="Disabled" },
    @{ Name="PowerShell Logging"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key="EnableScriptBlockLogging"; Safe="Enabled"; Warning="Disabled" },
    @{ Name="Activities Cache"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key="EnableActivityFeed"; Safe="Enabled"; Warning="Disabled" }
)

foreach ($s in $settings) {
    # Vérifier UNIQUEMENT si le chemin existe
    if (Test-Path $s.Path) {
        $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
        if ($status) {
            if ($status.$($s.Key) -eq 0) {
                # Désactivé → réparer
                try {
                    Set-ItemProperty -Path $s.Path -Name $s.Key -Value 1 -Force
                    $statusText = "$($s.Warning) → Réactivé ✅"
                    $color = "Green"
                } catch {
                    $statusText = "$($s.Warning) → Réactivation échouée ❌"
                    $color = "Red"
                }
            } else {
                $statusText = "$($s.Safe) ✅"
                $color = "Cyan"
            }
        } else {
            $statusText = "Clé absente dans ce chemin [Info]"
            $color = "Yellow"
        }
    } else {
        # Si le chemin n'existe pas, c'est normal pour la plupart des systèmes
        $statusText = "Chemin non trouvé [Normal]"
        $color = "Yellow"
    }
    
    $report += [PSCustomObject]@{
        Item = $s.Name
        Type = "Paramètre"
        Status = $statusText
        Color = $color
    }
}

# 3️⃣ Affichage du rapport
Write-Host "================= Check-Up Windows =================" -ForegroundColor Yellow
foreach ($r in $report) {
    Write-Host ("{0,-20} | {1,-10} | {2}" -f $r.Item, $r.Type, $r.Status) -ForegroundColor $r.Color
}
Write-Host "===================================================" -ForegroundColor Yellow
Write-Host "Check complete." -ForegroundColor Green

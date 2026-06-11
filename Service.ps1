# ===============================================
# PowerShell Admin Check-Up + Réactivation (FIXED)
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

# 2️⃣ Paramètres Windows (AVEC création de chemins manquants)
$settings = @(
    @{ Name="CMD"; Path="HKCU:\Software\Policies\Microsoft\Windows\System"; Key="DisableCMD"; Safe="Available"; Warning="Disabled" },
    @{ Name="PowerShell Logging"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Key="EnableScriptBlockLogging"; Safe="Enabled"; Warning="Disabled" },
    @{ Name="Activities Cache"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Key="EnableActivityFeed"; Safe="Enabled"; Warning="Disabled" }
)

foreach ($s in $settings) {
    # Vérifier si le chemin existe, sinon le créer
    if (-not (Test-Path $s.Path)) {
        try {
            New-Item -Path $s.Path -Force | Out-Null
        } catch {
            Write-Host "Impossible de créer le chemin: $($s.Path)" -ForegroundColor Red
        }
    }
    
    $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue
    if ($status) {
        if ($status.$($s.Key) -eq 0) {
            # Désactivé → réparer si possible
            try {
                Set-ItemProperty -Path $s.Path -Name $s.Key -Value 1 -Force
                $statusText = "$($s.Warning) → Réactivé ✅ [Option PC]"
                $color = "Green"
            } catch {
                $statusText = "$($s.Warning) → Réactivation échouée ❌ [Option PC]"
                $color = "Red"
            }
        } else {
            $statusText = "$($s.Safe) [Option PC]"
            $color = "Cyan"
        }
    } else {
        # Clé absente → créer maintenant que le chemin existe
        try {
            New-ItemProperty -Path $s.Path -Name $s.Key -PropertyType DWORD -Value 1 -Force | Out-Null
            $statusText = "Clé manquante → Créée ✅ [Bypass possible]"
            $color = "Green"
        } catch {
            $statusText = "Clé manquante → Échec ❌ [Bypass possible]"
            $color = "Red"
        }
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

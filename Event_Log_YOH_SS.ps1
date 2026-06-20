<#
.SYNOPSIS
    Lecture propre et horodatee des journaux d'evenements Windows utiles en screenshare
    (nettoyage de traces, Defender, sessions, processus, services, VSS/Shadow Copies,
    disques virtuels, peripheriques).

.DESCRIPTION
    Interroge chaque journal Windows avec les bons EventID, affiche un rapport lisible
    (horodatage, journal, ID, niveau, libelle, ordinateur, message) et peut exporter
    le tout en CSV.

.PARAMETER Days
    Nombre de jours a remonter dans le passe (defaut : 7).

.PARAMETER StartTime
    Date/heure de debut (prioritaire sur -Days si fournie). Ex : "2025-06-01 00:00".

.PARAMETER EndTime
    Date/heure de fin (defaut : maintenant).

.PARAMETER CsvPath
    Chemin d'export CSV. Si omis, aucun export.

.PARAMETER MaxEvents
    Limite d'evenements par journal (0 = pas de limite, defaut).

.PARAMETER FullMessage
    Affiche le message complet en console (sinon tronque a 400 caracteres).

.EXAMPLE
    .\Lecture-EventLogs-Screenshare.ps1 -Days 3

.EXAMPLE
    .\Lecture-EventLogs-Screenshare.ps1 -StartTime "2025-06-19 18:00" -CsvPath "$env:USERPROFILE\Desktop\events.csv"

.NOTES
    A executer dans un PowerShell en tant qu'ADMINISTRATEUR
    (le journal Security n'est lisible qu'avec des droits eleves).
#>

[CmdletBinding()]
param(
    [int]      $Days = 7,
    [datetime] $StartTime,
    [datetime] $EndTime = (Get-Date),
    [string]   $CsvPath,
    [int]      $MaxEvents = 0,
    [switch]   $FullMessage
)

# ----------------------------------------------------------------------------
# 0. Verification des droits administrateur
# ----------------------------------------------------------------------------
$estAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $estAdmin) {
    Write-Warning "Ce script n'est PAS lance en administrateur. Le journal 'Security' sera probablement inaccessible."
    Write-Warning "Relance PowerShell avec 'Executer en tant qu'administrateur' pour un resultat complet.`n"
}

# ----------------------------------------------------------------------------
# 1. Plage horaire
# ----------------------------------------------------------------------------
if (-not $StartTime) { $StartTime = $EndTime.AddDays(-$Days) }

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Lecture des Event Logs" -ForegroundColor Cyan
Write-Host " Du : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host " Au : $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# 2. Definition des evenements surveilles
#    (Id, vrai LogName, Categorie, Libelle)
# ----------------------------------------------------------------------------
$EventDefs = @(
    # --- Nettoyage de traces / Alteration systeme ---
    [pscustomobject]@{ Id=1102;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Journal d'audit de securite supprime." }
    [pscustomobject]@{ Id=1100;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Service de journalisation arrete." }
    [pscustomobject]@{ Id=1108;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Echec d'ecriture dans le journal d'audit." }
    [pscustomobject]@{ Id=104;   Log='System';      Categorie='Nettoyage/Alteration'; Libelle="Journal d'evenements supprime." }
    [pscustomobject]@{ Id=104;   Log='Application'; Categorie='Nettoyage/Alteration'; Libelle="Journal d'evenements supprime." }
    [pscustomobject]@{ Id=4719;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Politique d'audit modifiee." }
    [pscustomobject]@{ Id=4616;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Heure systeme modifiee." }
    [pscustomobject]@{ Id=4660;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Objet protege supprime." }
    [pscustomobject]@{ Id=4663;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Tentative d'acces a un objet protege." }
    [pscustomobject]@{ Id=4656;  Log='Security';    Categorie='Nettoyage/Alteration'; Libelle="Demande d'acces a un objet protege." }

    # --- Windows Defender ---
    [pscustomobject]@{ Id=5001;  Log='Microsoft-Windows-Windows Defender/Operational'; Categorie='Defender'; Libelle="Protection temps reel desactivee." }
    [pscustomobject]@{ Id=5004;  Log='Microsoft-Windows-Windows Defender/Operational'; Categorie='Defender'; Libelle="Service Windows Defender arrete." }

    # --- Comptes / Sessions ---
    [pscustomobject]@{ Id=4624;  Log='Security';    Categorie='Comptes/Sessions'; Libelle="Connexion reussie." }
    [pscustomobject]@{ Id=4634;  Log='Security';    Categorie='Comptes/Sessions'; Libelle="Session fermee." }
    [pscustomobject]@{ Id=4647;  Log='Security';    Categorie='Comptes/Sessions'; Libelle="Deconnexion initiee par l'utilisateur." }
    [pscustomobject]@{ Id=4672;  Log='Security';    Categorie='Comptes/Sessions'; Libelle="Attribution de privileges administrateur." }
    [pscustomobject]@{ Id=4720;  Log='Security';    Categorie='Comptes/Sessions'; Libelle="Creation d'un compte utilisateur." }

    # --- Processus / Execution ---
    [pscustomobject]@{ Id=4688;  Log='Security';    Categorie='Processus'; Libelle="Nouveau processus cree. (audit Process Creation requis)" }
    [pscustomobject]@{ Id=4689;  Log='Security';    Categorie='Processus'; Libelle="Processus termine. (audit Process Creation requis)" }
    [pscustomobject]@{ Id=4697;  Log='Security';    Categorie='Processus'; Libelle="Service installe sur le systeme." }

    # --- Services Windows ---
    [pscustomobject]@{ Id=7036;  Log='System';      Categorie='Services'; Libelle="Service demarre ou arrete." }
    [pscustomobject]@{ Id=6005;  Log='System';      Categorie='Services'; Libelle="Service de journalisation demarre." }
    [pscustomobject]@{ Id=6006;  Log='System';      Categorie='Services'; Libelle="Service de journalisation arrete." }

    # --- Shadow Copies / VSS ---
    [pscustomobject]@{ Id=13;    Log='Application'; Categorie='VSS/ShadowCopy'; Libelle="Shadow Copy creee." }
    [pscustomobject]@{ Id=14;    Log='Application'; Categorie='VSS/ShadowCopy'; Libelle="Shadow Copy supprimee." }
    [pscustomobject]@{ Id=8193;  Log='Application'; Categorie='VSS/ShadowCopy'; Libelle="Erreur VSS." }
    [pscustomobject]@{ Id=8193;  Log='System';      Categorie='VSS/ShadowCopy'; Libelle="Erreur VSS." }
    [pscustomobject]@{ Id=8224;  Log='Application'; Categorie='VSS/ShadowCopy'; Libelle="Erreur interne VSS." }
    [pscustomobject]@{ Id=8228;  Log='Application'; Categorie='VSS/ShadowCopy'; Libelle="Erreur d'un composant VSS." }
    [pscustomobject]@{ Id=12289; Log='System';      Categorie='VSS/ShadowCopy'; Libelle="Creation/suppression de Shadow Copy (volsnap)." }
    [pscustomobject]@{ Id=12289; Log='Application'; Categorie='VSS/ShadowCopy'; Libelle="Creation/suppression de Shadow Copy." }

    # --- Disques virtuels (VHD) ---
    [pscustomobject]@{ Id=100;   Log='Microsoft-Windows-VHDMP/Operational'; Categorie='Disques virtuels'; Libelle="Disque virtuel (VHD) monte." }
    [pscustomobject]@{ Id=101;   Log='Microsoft-Windows-VHDMP/Operational'; Categorie='Disques virtuels'; Libelle="Disque virtuel (VHD) demonte." }

    # --- Peripheriques ---
    [pscustomobject]@{ Id=6416;  Log='Security';    Categorie='Peripheriques'; Libelle="Nouveau peripherique detecte." }
    [pscustomobject]@{ Id=6420;  Log='Security';    Categorie='Peripheriques'; Libelle="Peripherique desactive." }
)

# Table de correspondance "Log|Id" -> Libelle (pour retrouver le libelle apres requete)
$libelleLookup = @{}
foreach ($d in $EventDefs) { $libelleLookup["$($d.Log)|$($d.Id)"] = $d.Libelle }
$catLookup = @{}
foreach ($d in $EventDefs) { $catLookup["$($d.Log)|$($d.Id)"] = $d.Categorie }

# ----------------------------------------------------------------------------
# 3. Interrogation de chaque journal
# ----------------------------------------------------------------------------
$resultats = New-Object System.Collections.Generic.List[object]

$groupes = $EventDefs | Group-Object Log

foreach ($g in $groupes) {
    $logName = $g.Name
    $ids     = $g.Group.Id | Select-Object -Unique

    # Le journal existe-t-il et est-il activable ?
    $logInfo = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if (-not $logInfo) {
        Write-Warning "Journal indisponible (inexistant ou desactive) : $logName"
        continue
    }

    $filtre = @{
        LogName   = $logName
        Id        = $ids
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    try {
        if ($MaxEvents -gt 0) {
            $evts = Get-WinEvent -FilterHashtable $filtre -MaxEvents $MaxEvents -ErrorAction Stop
        } else {
            $evts = Get-WinEvent -FilterHashtable $filtre -ErrorAction Stop
        }
    }
    catch {
        # "No events were found" / "Aucun evenement" = normal, on passe
        if ($_.Exception.Message -match 'No events were found|Aucun') {
            $evts = @()
        }
        else {
            Write-Warning "Erreur sur le journal '$logName' : $($_.Exception.Message)"
            $evts = @()
        }
    }

    foreach ($e in $evts) {
        $cle = "$logName|$($e.Id)"
        $resultats.Add([pscustomobject]@{
            Horodatage  = $e.TimeCreated
            Journal     = $logName
            EventId     = $e.Id
            Niveau      = $e.LevelDisplayName
            Categorie   = $catLookup[$cle]
            Libelle     = $libelleLookup[$cle]
            Ordinateur  = $e.MachineName
            Utilisateur = if ($e.UserId) { $e.UserId.Value } else { '' }
            Message     = ($e.Message -replace '\s+', ' ').Trim()
        })
    }
}

# ----------------------------------------------------------------------------
# 4. Affichage console (trie par horodatage)
# ----------------------------------------------------------------------------
$resultats = $resultats | Sort-Object Horodatage

if ($resultats.Count -eq 0) {
    Write-Host "`nAucun evenement trouve sur la periode demandee." -ForegroundColor Yellow
    return
}

$couleurs = @{
    'Nettoyage/Alteration' = 'Red'
    'Defender'             = 'Magenta'
    'Comptes/Sessions'     = 'Green'
    'Processus'            = 'Cyan'
    'Services'             = 'Gray'
    'VSS/ShadowCopy'       = 'Yellow'
    'Disques virtuels'     = 'Blue'
    'Peripheriques'        = 'White'
}

foreach ($r in $resultats) {
    $coul = $couleurs[$r.Categorie]; if (-not $coul) { $coul = 'White' }
    $ts   = $r.Horodatage.ToString('yyyy-MM-dd HH:mm:ss')

    Write-Host ("[{0}] " -f $ts) -ForegroundColor DarkGray -NoNewline
    Write-Host ("{0}  ID {1}  " -f $r.Journal, $r.EventId) -ForegroundColor $coul -NoNewline
    Write-Host ("({0})" -f $r.Categorie) -ForegroundColor DarkGray
    Write-Host ("    -> {0}" -f $r.Libelle) -ForegroundColor $coul
    Write-Host ("    Ordinateur: {0} | Niveau: {1}" -f $r.Ordinateur, $r.Niveau) -ForegroundColor DarkGray

    $msg = $r.Message
    if (-not $FullMessage -and $msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
    Write-Host ("    Message: {0}" -f $msg) -ForegroundColor DarkGray
    Write-Host ""
}

# ----------------------------------------------------------------------------
# 5. Recapitulatif par EventId
# ----------------------------------------------------------------------------
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Recapitulatif ($($resultats.Count) evenements)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$resultats |
    Group-Object Journal, EventId |
    Sort-Object Count -Descending |
    ForEach-Object {
        Write-Host ("  {0,5} x  {1}" -f $_.Count, $_.Name)
    }

# ----------------------------------------------------------------------------
# 6. Export CSV optionnel
# ----------------------------------------------------------------------------
if ($CsvPath) {
    try {
        $resultats | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nExport CSV : $CsvPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Echec de l'export CSV : $($_.Exception.Message)"
    }
}

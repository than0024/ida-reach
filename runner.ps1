param(
    [switch]$clean,
    [switch]$force,
    [string]$src = "C:\Windows\System32",
    [string]$out = "$PSScriptRoot\BinsDB"
)

# please make sure you IDA in your PATH!
$cfg = @{
    dbghelp_path = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll"
    symbol_path  = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
    src          = $src
    db_dir       = $out
    max_jobs     = 20
    exts         = @(".dll", ".exe", ".sys", ".efi")
    exclude_dirs = @()
}

function get_hash([string]$path, [int]$len = 8) {
    (Get-FileHash $path -Algorithm SHA256).Hash.Substring(0, $len).ToLower()
}

function rm_db([string]$db_dir, [bool]$force_rm) {
    if (-not (Test-Path $db_dir)) {
        Write-Output "db dir doesn't exist"
        return
    }
    if (-not $force_rm) {
        $cnt = (Get-ChildItem $db_dir -Directory -EA SilentlyContinue).Count
        $ans = Read-Host "delete $cnt dirs in $db_dir? (y/N)"
        if ($ans -ne 'y') { Write-Output "abort"; exit 0 }
    }
    Write-Output "removing db..."
    Remove-Item $db_dir -Recurse -Force -EA SilentlyContinue
}

function get_bins([string]$path, [string[]]$exts, [string[]]$exclude) {
    $files = Get-ChildItem $path -Recurse -File -EA SilentlyContinue |
        Where-Object { $_.Extension -in $exts }
    if ($exclude.Count -gt 0) {
        $pat = "\\(" + ($exclude -join "|") + ")\\"
        $files = $files | Where-Object { $_.FullName -notmatch $pat }
    }
    $files | Select-Object -ExpandProperty FullName
}

function copy_to_db([string[]]$files, [string]$db_dir) {
    $stats = @{ copied = 0; skipped = 0 }
    $paths = [Collections.ArrayList]::new()
    
    foreach ($src in $files) {
        $name = [IO.Path]::GetFileNameWithoutExtension($src)
        $fname = [IO.Path]::GetFileName($src)
        $hash = get_hash $src
        
        $dest_dir = Join-Path $db_dir $name | Join-Path -ChildPath $hash
        $dest = Join-Path $dest_dir $fname
        
        if (Test-Path $dest) {
            $stats.skipped++
        } else {
            Write-Output "[+] $fname -> $name/$hash/"
            New-Item -ItemType Directory -Path $dest_dir -Force -EA SilentlyContinue | Out-Null
            Copy-Item $src $dest -Force -EA SilentlyContinue
            $src | Out-File (Join-Path $dest_dir ".source") -Encoding UTF8 -Force
            $stats.copied++
        }
        [void]$paths.Add($dest)
    }
    @{ paths = $paths; stats = $stats }
}

function get_pending([string[]]$paths) {
    $pending = [Collections.ArrayList]::new()
    foreach ($p in $paths) {
        $dir = [IO.Path]::GetDirectoryName($p)
        if (-not (Test-Path (Join-Path $dir ".complete")) -and -not (Test-Path (Join-Path $dir ".processing"))) {
            [void]$pending.Add($p)
        }
    }
    $pending
}

function split_arr([array]$arr, [int]$parts) {
    if ($arr.Count -eq 0) { return @() }
    $sz = [Math]::Ceiling($arr.Count / $parts)
    $chunks = [Collections.ArrayList]::new()
    for ($i = 0; $i -lt $arr.Count; $i += $sz) {
        $chunk = [Collections.ArrayList]::new()
        $end = [Math]::Min($i + $sz, $arr.Count)
        for ($j = $i; $j -lt $end; $j++) { [void]$chunk.Add($arr[$j]) }
        [void]$chunks.Add($chunk.ToArray())
    }
    $chunks.ToArray()
}

$job_script = {
    param([array]$bins, [string]$root, [int]$id, [string]$db_dir)
    
    if ($env:Path -notlike "*$root\IDA*") { $env:Path += ";$root\IDA" }
    $cnt = 0
    
    foreach ($bin in $bins) {
        $dir = [IO.Path]::GetDirectoryName($bin)
        $name = [IO.Path]::GetFileName($bin)
        $complete = Join-Path $dir ".complete"
        $processing = Join-Path $dir ".processing"
        
        if (Test-Path $complete) {
            Write-Output "[J$id] skip: $name"
            continue
        }
        
        try { New-Item $processing -ItemType File -EA Stop | Out-Null }
        catch { Write-Output "[J$id] locked: $name"; continue }
        
        Write-Output "[J$id] start: $name"
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
        New-Item (Join-Path $dir "analysis_results.idaout") -ItemType File -Force | Out-Null
        
        # you need to have ida in your PATH!
        [Diagnostics.Process]::Start("ida.exe", "-c -A -S`"$root\analyze.py`" $bin").WaitForExit(10000000) | Out-Null
        
        Remove-Item $processing -EA SilentlyContinue
        New-Item $complete -ItemType File -Force | Out-Null
        
        $result = Get-Content (Join-Path $dir "analysis_results.idaout") -EA SilentlyContinue
        $status = if ($result) { "done" } else { "ERR" }
        Write-Output "[J${id}] ${status}: $name"
        $cnt++
    }
    "[J$id] processed $cnt"
}

if ($clean) {
    rm_db $cfg.db_dir $force
    exit 0
}

Write-Output "searching $($cfg.src)..."
$bins = @(get_bins $cfg.src $cfg.exts $cfg.exclude_dirs)
Write-Output "found $($bins.Count) binaries"

Write-Output "sync with db..."
New-Item -ItemType Directory -Path $cfg.db_dir -Force -EA SilentlyContinue | Out-Null
$db = copy_to_db $bins $cfg.db_dir
Write-Output "copied: $($db.stats.copied), skipped: $($db.stats.skipped)"

$pending = @(get_pending $db.paths)
$total = $db.paths.Count

if ($pending.Count -eq 0) {
    Write-Output "all $total done"
    exit 0
}

Write-Output "pending: $($pending.Count) / $total"

$chunks = split_arr $pending $cfg.max_jobs
Write-Output "starting $($chunks.Count) jobs..."

$jobs = @()
for ($i = 0; $i -lt $chunks.Count; $i++) {
    Write-Output "[+] job ${i}: $($chunks[$i].Count) bins\n"
    $jobs += Start-Job -ScriptBlock $job_script -ArgumentList $chunks[$i], $PSScriptRoot, $i, $cfg.db_dir
}

while (Get-Job -State Running) {
    $done = (Get-ChildItem "$($cfg.db_dir)\*\*\.complete" -EA SilentlyContinue).Count
    $active = (Get-ChildItem "$($cfg.db_dir)\*\*\.processing" -EA SilentlyContinue).Count
    Write-Host "`r[progress] done: $done/$total | active: $active    " -NoNewline
    $jobs | Receive-Job
    Start-Sleep -Seconds 2
}

Write-Host ""
$jobs | ForEach-Object {
    Write-Output "`njob $($_.Id):"
    Receive-Job $_
    Remove-Job $_
}

$final = (Get-ChildItem "$($cfg.db_dir)\*\*\.complete" -EA SilentlyContinue).Count
Write-Output "complete: $final / $total"

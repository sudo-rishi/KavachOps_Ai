$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$pythonMl = Join-Path $root "python-ml"
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$envFile = Join-Path $root ".env"

if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Project .env file not found. Create it from the project's required configuration."
}

function Read-ProjectEnvironment {
    param([string]$Path)

    $values = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $entry = $line.Trim()
        if (-not $entry -or $entry.StartsWith("#")) {
            continue
        }
        if ($entry.StartsWith("export ")) {
            $entry = $entry.Substring(7).Trim()
        }

        $separator = $entry.IndexOf("=")
        if ($separator -lt 1) {
            continue
        }

        $name = $entry.Substring(0, $separator).Trim()
        if ($name -match "^[A-Za-z_][A-Za-z0-9_]*$") {
            $environmentName = $name
        }
        elseif ($name -match "^[A-Za-z][A-Za-z0-9_.-]*$") {
            $environmentName = $name.Replace(".", "_").Replace("-", "_").ToUpperInvariant()
        }
        else {
            continue
        }

        $value = $entry.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and
            (($value.StartsWith('"') -and $value.EndsWith('"')) -or
             ($value.StartsWith("'") -and $value.EndsWith("'")))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        if ($value) {
            $values[$environmentName] = $value
        }
    }

    foreach ($environmentName in @($values.Keys)) {
        $placeholder = [regex]::Match(
            [string]$values[$environmentName],
            '^\$\{(?<name>[A-Za-z_][A-Za-z0-9_]*)(?::(?<fallback>.*))?\}$'
        )
        if (-not $placeholder.Success) {
            continue
        }

        $referencedValue = [Environment]::GetEnvironmentVariable(
            $placeholder.Groups["name"].Value,
            "Process"
        )
        if ($referencedValue) {
            $values[$environmentName] = $referencedValue
        }
        elseif ($placeholder.Groups["fallback"].Success) {
            $values[$environmentName] = $placeholder.Groups["fallback"].Value
        }
        else {
            $values[$environmentName] = ""
        }
    }

    return $values
}

function Get-ConfigValue {
    param(
        [hashtable]$FileValues,
        [string]$Name,
        [string]$Default = ""
    )

    if ($FileValues.ContainsKey($Name)) {
        return [string]$FileValues[$Name]
    }

    $processValue = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ($processValue) {
        return $processValue
    }
    return $Default
}

function Test-TcpEndpoint {
    param([string]$HostName, [int]$Port)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connection = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $connection.AsyncWaitHandle.WaitOne(2000)) {
            return $false
        }
        $client.EndConnect($connection)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Assert-PortFree {
    param([int]$Port, [string]$Service)

    $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($listener) {
        throw "$Service port $Port is already in use. Stop that process before launching the stack."
    }
}

function Start-ServiceConsole {
    param(
        [string]$Title,
        [string]$WorkingDirectory,
        [string]$Command,
        [hashtable]$Environment,
        [string[]]$ClearEnvironment = @()
    )

    $previousValues = @{}
    $changedNames = @($Environment.Keys) + @($ClearEnvironment) | Select-Object -Unique
    foreach ($name in $changedNames) {
        $previousValues[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    foreach ($name in $ClearEnvironment) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    foreach ($name in $Environment.Keys) {
        [Environment]::SetEnvironmentVariable($name, [string]$Environment[$name], "Process")
    }

    try {
        $quotedDirectory = $WorkingDirectory.Replace("'", "''")
        $quotedTitle = $Title.Replace("'", "''")
        $consoleCommand = "`$Host.UI.RawUI.WindowTitle = '$quotedTitle'; Set-Location -LiteralPath '$quotedDirectory'; $Command"
        $encodedCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($consoleCommand)
        )
        return Start-Process -FilePath "powershell.exe" `
            -WorkingDirectory $WorkingDirectory `
            -ArgumentList @("-NoExit", "-EncodedCommand", $encodedCommand) `
            -PassThru
    }
    finally {
        foreach ($name in $changedNames) {
            [Environment]::SetEnvironmentVariable($name, $previousValues[$name], "Process")
        }
    }
}

function Wait-ForHttp {
    param(
        [string]$Name,
        [string]$Uri,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = "No response yet"
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
                return $response
            }
            $lastError = "HTTP status $($response.StatusCode)"
        }
        catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }

    throw "$Name did not become ready at $Uri. Last check: $lastError"
}

$projectEnvironment = Read-ProjectEnvironment -Path $envFile
$pythonEnvironment = @{}
$backendEnvironment = @{}
$frontendEnvironment = @{}
foreach ($name in $projectEnvironment.Keys) {
    $pythonEnvironment[$name] = $projectEnvironment[$name]
    $backendEnvironment[$name] = $projectEnvironment[$name]
    if ($name.StartsWith("VITE_")) {
        $frontendEnvironment[$name] = $projectEnvironment[$name]
    }
}

$sarvamKey = Get-ConfigValue -FileValues $projectEnvironment -Name "SARVAM_API_KEY"
if (-not $sarvamKey) {
    $sarvamKey = Get-ConfigValue -FileValues $projectEnvironment -Name "KAVACHOPSAI_SARVAM_API_KEY"
}
if ($sarvamKey -and -not $backendEnvironment.ContainsKey("KAVACHOPSAI_SARVAM_API_KEY")) {
    $backendEnvironment["KAVACHOPSAI_SARVAM_API_KEY"] = $sarvamKey
}

$jwtSecret = Get-ConfigValue -FileValues $projectEnvironment -Name "KAVACHOPSAI_JWT_SECRET"
if ([System.Text.Encoding]::UTF8.GetByteCount($jwtSecret) -lt 32) {
    throw "KAVACHOPSAI_JWT_SECRET must be set in .env and contain at least 32 bytes."
}

$bootstrapEnabled = Get-ConfigValue -FileValues $projectEnvironment -Name "KAVACHOPSAI_BOOTSTRAP_ADMIN_ENABLED"
if ($bootstrapEnabled -eq "true") {
    $bootstrapPassword = Get-ConfigValue -FileValues $projectEnvironment -Name "KAVACHOPSAI_BOOTSTRAP_ADMIN_PASSWORD"
    if ($bootstrapPassword.Length -lt 12) {
        throw "When admin bootstrap is enabled, set a password of at least 12 characters in .env."
    }
}

foreach ($command in @("py", "npm", "mvn", "java", "powershell.exe")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' was not found on PATH."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $frontend "node_modules"))) {
    throw "Frontend dependencies are missing. Run 'npm install' in the frontend directory first."
}
& py -3.12 -c "import flask, numpy, pandas, sklearn, sarvamai, reportlab"
if ($LASTEXITCODE -ne 0) {
    throw "Python ML dependencies are missing for Python 3.12. Install python-ml\requirements.txt with py -3.12."
}

$jdbcUrl = Get-ConfigValue -FileValues $projectEnvironment -Name "SPRING_DATASOURCE_URL" -Default "jdbc:postgresql://localhost:5432/kavachopsai"
$databaseMatch = [regex]::Match($jdbcUrl, "^jdbc:postgresql://(?<host>\[[^\]]+\]|[^:/?]+)(?::(?<port>\d+))?")
if (-not $databaseMatch.Success) {
    throw "SPRING_DATASOURCE_URL must be a PostgreSQL JDBC URL."
}
$databaseHost = $databaseMatch.Groups["host"].Value.TrimStart("[").TrimEnd("]")
$databasePort = 5432
if ($databaseMatch.Groups["port"].Success) {
    $databasePort = [int]$databaseMatch.Groups["port"].Value
}
if (-not (Test-TcpEndpoint -HostName $databaseHost -Port $databasePort)) {
    throw "PostgreSQL is not reachable at ${databaseHost}:$databasePort. Start the database and retry."
}

$mlPort = [int](Get-ConfigValue -FileValues $projectEnvironment -Name "ML_APP_PORT" -Default "5000")
$backendPort = [int](Get-ConfigValue -FileValues $projectEnvironment -Name "SERVER_PORT" -Default "8081")
$contextPath = Get-ConfigValue -FileValues $projectEnvironment -Name "SERVER_SERVLET_CONTEXT_PATH" -Default "/api"
$contextPath = "/" + $contextPath.Trim("/")
$mlHost = Get-ConfigValue -FileValues $projectEnvironment -Name "ML_APP_HOST" -Default "127.0.0.1"
$mlHealthHost = $mlHost
if ($mlHealthHost -eq "0.0.0.0") {
    $mlHealthHost = "127.0.0.1"
}

Assert-PortFree -Port $mlPort -Service "Python ML"
Assert-PortFree -Port $backendPort -Service "Spring API"
Assert-PortFree -Port 5173 -Service "Vite frontend"

$javaVersion = (& $env:ComSpec /d /c "java -version 2>&1" | Out-String)
$javaExitCode = $LASTEXITCODE
$javaMajor = [regex]::Match($javaVersion, 'version "(\d+)').Groups[1].Value
if ($javaExitCode -ne 0 -or -not $javaMajor -or [int]$javaMajor -lt 25) {
    throw "Java 25 or newer is required by the backend."
}

Write-Host "Starting Python ML service..."
$pythonProcess = Start-ServiceConsole -Title "KavachOps Python ML" `
    -WorkingDirectory $pythonMl -Command "py -3.12 app.py" -Environment $pythonEnvironment
$mlUri = "http://${mlHealthHost}:$mlPort/api/health"
$null = Wait-ForHttp -Name "Python ML service" -Uri $mlUri -TimeoutSeconds 120

Write-Host "Starting Spring backend..."
$backendProcess = Start-ServiceConsole -Title "KavachOps Spring API" `
    -WorkingDirectory $backend -Command "mvn spring-boot:run" -Environment $backendEnvironment
$backendUri = "http://localhost:$backendPort$contextPath/actuator/health"
$null = Wait-ForHttp -Name "Spring backend" -Uri $backendUri -TimeoutSeconds 180

Write-Host "Starting frontend..."
$frontendClearEnvironment = @($projectEnvironment.Keys) + @(
    "SARVAM_API_KEY",
    "KAVACHOPSAI_SARVAM_API_KEY",
    "KAVACHOPSAI_JWT_SECRET",
    "KAVACHOPSAI_BOOTSTRAP_ADMIN_PASSWORD",
    "SPRING_DATASOURCE_PASSWORD"
)
$frontendProcess = Start-ServiceConsole -Title "KavachOps Frontend" `
    -WorkingDirectory $frontend -Command "npm run dev" -Environment $frontendEnvironment `
    -ClearEnvironment $frontendClearEnvironment
$null = Wait-ForHttp -Name "Frontend" -Uri "http://localhost:5173" -TimeoutSeconds 60

$sarvamStatus = "not configured"
if ($sarvamKey) {
    $sarvamStatus = "configured"
}
Write-Host "KavachOps is running: http://localhost:5173"
Write-Host "Python ML: $mlUri"
Write-Host "Spring API: $backendUri"
Write-Host "Sarvam key: $sarvamStatus (no Sarvam request was sent)"
Write-Host "Console process IDs: ML=$($pythonProcess.Id), API=$($backendProcess.Id), frontend=$($frontendProcess.Id)"

# Install script for Antigravity Controller on Windows
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Antigravity Controller - Windows Installation " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify .NET SDK
Write-Host "Checking .NET SDK..." -ForegroundColor Yellow
try {
    $dotnetVersion = & dotnet --version
    Write-Host "Found .NET SDK version: $dotnetVersion" -ForegroundColor Green
} catch {
    Write-Error ".NET SDK was not found. Please install the .NET 10 SDK: https://dotnet.microsoft.com/download"
    exit 1
}

# 2. Check for logiplugintool
Write-Host "`nChecking logiplugintool..." -ForegroundColor Yellow
$tool = Get-Command "logiplugintool" -ErrorAction SilentlyContinue
if (-not $tool) {
    $userToolPath = Join-Path $env:USERPROFILE ".dotnet\tools\logiplugintool.exe"
    if (Test-Path $userToolPath) {
        $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
        $tool = Get-Command "logiplugintool" -ErrorAction SilentlyContinue
    }
}

if (-not $tool) {
    Write-Host "logiplugintool not found in PATH. Installing LogiPluginTool globally..." -ForegroundColor Yellow
    & dotnet tool install --global logiplugintool
    $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
}

# 3. Build Release
$srcDir = Join-Path $PSScriptRoot "src"
$binReleaseDir = Join-Path $PSScriptRoot "bin\Release"
$packagePath = Join-Path $PSScriptRoot "AntigravityController.lplug4"

Write-Host "`nBuilding Antigravity Controller (Release)..." -ForegroundColor Yellow
& dotnet build -c Release $srcDir
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed."
    exit 1
}

# 4. Pack .lplug4
Write-Host "`nPackaging plugin (.lplug4)..." -ForegroundColor Yellow
if (Test-Path $packagePath) {
    Remove-Item $packagePath -Force
}
& logiplugintool pack $binReleaseDir $packagePath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Packaging failed."
    exit 1
}

# 5. Verify package
Write-Host "`nVerifying package..." -ForegroundColor Yellow
& logiplugintool verify $packagePath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Package verification failed."
    exit 1
}

# 6. Install package
Write-Host "`nInstalling plugin to Logi Plugin Service..." -ForegroundColor Yellow
& logiplugintool install $packagePath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Installation failed."
    exit 1
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " Antigravity Controller successfully installed on Windows!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "The plugin is now active in Logi Options+ / Logi Plugin Service"
Write-Host "and ready to control Antigravity and Antigravity IDE."

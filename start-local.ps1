$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "Northstar - Local Setup" -ForegroundColor Cyan
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw "Python was not found. Install Python 3.11+ from https://www.python.org/downloads/ and enable Add Python to PATH." }
if (-not (Test-Path ".venv")) { Write-Host "Creating Python virtual environment..."; py -m venv .venv }
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
Write-Host "Installing backend dependencies..."
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt
if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  $secret = -join ((1..48 | ForEach-Object { "{0:x2}" -f (Get-Random -Maximum 256) }))
  (Get-Content ".env" -Raw).Replace("replace-this-with-a-long-random-secret", $secret) | Set-Content ".env"
  Write-Host "Created local .env with a generated development secret."
}
Write-Host "Starting Northstar at http://localhost:8000" -ForegroundColor Green
Write-Host "Keep this window open while using the website. Press Ctrl+C to stop."
& $python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

# Build and upload to PyPI. Run scripts/check.ps1 first.
# The version must not already be on PyPI; the token is read from a secret store, never git.
$ErrorActionPreference = "Stop"

# $ErrorActionPreference does NOT stop on a native command's non-zero exit, so every
# native command runs through this check: a failed build or twine check must never upload.
function Invoke-Native($label, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$label failed (exit $LASTEXITCODE)" }
}

# Build only from a clean tree: hatchling ships every untracked, non-ignored file.
$dirty = Invoke-Native "git status" { git status --porcelain }
if ($dirty) { throw "The working tree is not clean. Commit or remove the changes first." }

# Refuse to upload a version PyPI already has. Works on Windows PowerShell 5.1 and pwsh 7.
$version = (Select-String -Path pyproject.toml -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$taken = $true
try {
    Invoke-WebRequest -UseBasicParsing "https://pypi.org/pypi/forwarded/$version/json" | Out-Null
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) { $taken = $false } else { throw }
}
if ($taken) { throw "forwarded $version is already on PyPI. Bump the version first." }

$token = $env:PYPI_TOKEN
if (-not $token -and (Test-Path "C:\secrets\pypi-token.txt")) {
    $token = (Get-Content "C:\secrets\pypi-token.txt" -Raw).Trim()
}
if (-not $token) {
    throw "No PyPI token. Set `$env:PYPI_TOKEN or save it to C:\secrets\pypi-token.txt (never commit it)."
}

Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
Invoke-Native "build" { python -m build }
Invoke-Native "twine check" { python -m twine check dist/* }

$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = $token
try { Invoke-Native "twine upload" { python -m twine upload dist/* } } finally { Remove-Item Env:\TWINE_PASSWORD -ErrorAction SilentlyContinue }

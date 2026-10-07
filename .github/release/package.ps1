#requires -Version 7
<#
  Архив релиза SignService для Windows x64:
    SignService-<версия>-win-x64.zip     — SignService.exe, README.txt, CHANGELOG.md,
                                           LICENSE.txt, licenses/, SHA256SUMS.txt;
    SignService-<версия>-win-x64.sha256  — SHA-256 архива и exe;
    RELEASE_NOTES.md                     — раздел версии из CHANGELOG.md для описания релиза.
  Лицензии пакетов NuGet берутся из графа восстановления после dotnet publish
  (включая пакет среды выполнения), тексты без файла в пакете — из licenses/ рядом.
  Запуск: pwsh .github/release/package.ps1 -PublishDir publish -OutputDir dist [-Tag v1.2.0]
#>
param(
    [Parameter(Mandatory)] [string] $PublishDir,
    [Parameter(Mandatory)] [string] $OutputDir,
    # Тег релиза: должен совпадать с версией проекта (иначе автообновление зациклится).
    [string] $Tag = ''
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$project = Join-Path $root 'src' 'SignService' 'SignService.csproj'
$version = ([xml](Get-Content $project -Raw)).Project.PropertyGroup.Version |
    Where-Object { $_ } | Select-Object -First 1
if (-not $version) { throw "В $project не указана версия." }
if ($Tag -and $Tag -ne "v$version") { throw "Тег $Tag не совпадает с версией проекта $version." }

$exe = Join-Path $PublishDir 'SignService.exe'
if (-not (Test-Path $exe)) { throw "Не найден $exe — сначала выполните dotnet publish." }

$name = "SignService-$version-win-x64"
New-Item -ItemType Directory -Force $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
$stage = Join-Path $OutputDir $name
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
$licenses = Join-Path $stage 'licenses'
New-Item -ItemType Directory -Force $licenses | Out-Null

function Write-Text([string] $path, [string[]] $lines) {
    # UTF-8 с BOM и CRLF — корректно открывается Блокнотом любой версии Windows.
    [IO.File]::WriteAllText($path, ($lines -join "`r`n") + "`r`n", [Text.UTF8Encoding]::new($true))
}

function Get-Sha256([string] $path) { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() }

Copy-Item $exe $stage
Copy-Item (Join-Path $root 'CHANGELOG.md') $stage
Copy-Item (Join-Path $root 'LICENSE') (Join-Path $stage 'LICENSE.txt')
Copy-Item (Join-Path $PSScriptRoot 'licenses' '*') $licenses

# Лицензии пакетов NuGet из графа восстановления: библиотеки и загруженные
# пакеты (среда выполнения win-x64 для самодостаточного exe).
$assets = Get-Content (Join-Path $root 'src' 'SignService' 'obj' 'project.assets.json') -Raw | ConvertFrom-Json
$packagesRoot = $assets.project.restore.packagesPath
$packages = [Collections.Generic.List[object]]::new()
foreach ($library in $assets.libraries.PSObject.Properties) {
    if ($library.Value.type -ne 'package') { continue }
    $id, $packageVersion = $library.Name -split '/', 2
    $packages.Add([pscustomobject]@{ Id = $id.ToLowerInvariant(); Version = $packageVersion; Path = $library.Value.path })
}
foreach ($framework in $assets.project.frameworks.PSObject.Properties) {
    foreach ($download in @($framework.Value.downloadDependencies)) {
        if (-not $download) { continue }
        $id = $download.name.ToLowerInvariant()
        $packageVersion = $download.version.Trim('[', ']', ' ').Split(',')[0].Trim()
        $packages.Add([pscustomobject]@{ Id = $id; Version = $packageVersion; Path = "$id/$packageVersion" })
    }
}

$copied = 0
foreach ($package in $packages | Sort-Object Id, Version -Unique) {
    $directory = Join-Path $packagesRoot $package.Path
    if (-not (Test-Path $directory)) { Write-Warning "Нет каталога пакета $directory"; continue }
    Get-ChildItem $directory -File |
        Where-Object { $_.Name -match '^(licen[cs]e|copying|notice|third-?party-?notices|thirdpartynotices)' } |
        ForEach-Object {
            Copy-Item $_.FullName (Join-Path $licenses "$($package.Id)-$($package.Version)-$($_.Name)")
            $copied++
        }
}
if ($copied -eq 0) { throw 'Не найдено ни одной лицензии пакетов NuGet — проверьте восстановление.' }

$repository = 'https://github.com/zaynullinmi/SignService'
Write-Text (Join-Path $stage 'README.txt') @(
    "SignService $version — Windows x64",
    '',
    'Запустите SignService.exe. Установка .NET не требуется.',
    'Подписание: перетащите файлы в окно, выберите сертификат и нажмите «Подписать».',
    'Проверка ЭЦП: «Инструменты → Проверить ЭЦП…» или ПКМ по файлу → «Подписанты и проверка ЭЦП…».',
    'Для откреплённой подписи нужен исходный документ.',
    'Проверка ГОСТ и операции с готовыми подписями работают без КриптоПро.',
    'Для создания новой ГОСТ-подписи требуется КриптоПро CSP и закрытый ключ.',
    'Результаты доверия, отзыва сертификатов и TSA указаны в отчёте проверки отдельно.',
    '',
    "Исходный код версии: $repository/tree/v$version",
    "Релиз: $repository/releases/tag/v$version",
    'Лицензии используемых компонентов находятся в каталоге licenses.'
)
# Формат sha256sum (без BOM): проверка — sha256sum -c SHA256SUMS.txt.
[IO.File]::WriteAllText((Join-Path $stage 'SHA256SUMS.txt'), "$(Get-Sha256 $exe)  SignService.exe`n",
    [Text.UTF8Encoding]::new($false))

$zip = Join-Path $OutputDir "$name.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
$zipHash = Get-Sha256 $zip
$exeHash = Get-Sha256 $exe
[IO.File]::WriteAllText((Join-Path $OutputDir "$name.sha256"),
    "$zipHash  $name.zip`n$exeHash  SignService.exe`n", [Text.UTF8Encoding]::new($false))

# Описание релиза — раздел этой версии из истории изменений.
$changelog = Get-Content (Join-Path $root 'CHANGELOG.md')
$start = [Array]::FindIndex([string[]] $changelog, [Predicate[string]] { param($line) $line -like "## v$version*" })
if ($start -lt 0) {
    if ($Tag) { throw "В CHANGELOG.md нет раздела «## v$version»." }
    $section = @("## v$version")
}
else {
    $end = [Array]::FindIndex([string[]] $changelog, $start + 1, [Predicate[string]] { param($line) $line -like '## *' })
    $last = if ($end -lt 0) { $changelog.Count - 1 } else { $end - 1 }
    while ($last -gt $start -and -not $changelog[$last].Trim()) { $last-- }
    $section = $changelog[$start..$last]
}
$notes = @($section) + @(
    '',
    '**Файлы**',
    '',
    '- `SignService.exe` — программа (Windows x64, установка .NET не требуется); этот файл скачивает автообновление;',
    "- ``$name.zip`` — программа с README, историей версий и лицензиями компонентов;",
    "- ``$name.sha256`` — контрольные суммы SHA-256.",
    '',
    '```',
    "$zipHash  $name.zip",
    "$exeHash  SignService.exe",
    '```'
)
[IO.File]::WriteAllText((Join-Path $OutputDir 'RELEASE_NOTES.md'), ($notes -join "`n") + "`n", [Text.UTF8Encoding]::new($false))

Write-Host "Архив: $zip"
Write-Host "Лицензий пакетов NuGet: $copied"
Write-Host "SHA-256: $zipHash  $name.zip"
Write-Host "SHA-256: $exeHash  SignService.exe"

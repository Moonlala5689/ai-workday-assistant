param([switch]$Tests, [switch]$TestsOnly)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $root 'build\consumer'
New-Item -ItemType Directory -Force -Path $out, (Join-Path $out 'logs'), (Join-Path $out 'test-data') | Out-Null
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw 'Windows .NET Framework x64 C# compiler not found.' }
$core = Join-Path $out 'WorkEnv.Consumer.Core.dll'
$coreSources = @('Core.cs','DirectProbe.cs','LocalState.cs','Records.cs','ServiceCheck.cs','DemoData.cs') | ForEach-Object { Join-Path "$root\core" $_ }
$functionalSources = @('Functional.cs','BrowserIce.cs','WorkflowScore.cs','ReadinessWfpShared.cs','ReadinessWfpClient.cs','ReadinessWfpProcess.cs') | ForEach-Object { Join-Path "$root\desktop" $_ }
& $csc /nologo /codepage:65001 /define:WORKFLOW,CONSUMER /target:library /platform:x64 /optimize+ /debug- /out:"$core" /reference:System.Core.dll /reference:System.Management.dll /reference:System.Web.Extensions.dll $coreSources
if ($LASTEXITCODE -ne 0) { throw 'Consumer core build failed.' }
if (-not $TestsOnly) {
 & $csc /nologo /codepage:65001 /define:WORKFLOW,CONSUMER /target:winexe /platform:x64 /optimize+ /debug- /win32manifest:"$root\desktop\Visual.manifest" /out:"$out\AI开工助手.exe" /reference:"$core" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "$root\desktop\Program.cs" "$root\desktop\VisualTheme.cs" "$root\desktop\ConsumerAssemblyInfo.cs" $functionalSources
 if ($LASTEXITCODE -ne 0) { throw 'Consumer desktop build failed.' }
 & $csc /nologo /codepage:65001 /target:exe /platform:x64 /optimize+ /debug- /out:"$out\WorkEnv.Consumer.Wfp.exe" /reference:System.Web.Extensions.dll "$root\desktop\ReadinessWfpHelper.cs" "$root\desktop\ReadinessWfpNative.cs" "$root\desktop\ReadinessWfpShared.cs"
 if ($LASTEXITCODE -ne 0) { throw 'Consumer WFP helper build failed.' }
}
$assetsOut = Join-Path $out 'assets'
New-Item -ItemType Directory -Force -Path $assetsOut | Out-Null
foreach ($asset in @('dbip-country-lite-2026-11.csv.gz','dbip-asn-lite-2026-11.csv.gz')) {
 $assetSource = Join-Path "$root\assets" $asset
 if (-not (Test-Path -LiteralPath $assetSource -PathType Leaf)) { throw "Required asset missing: $asset" }
 Copy-Item -LiteralPath $assetSource -Destination (Join-Path $assetsOut $asset) -Force
}
if ($Tests -or $TestsOnly) {
 foreach ($name in @('WorkflowTests','WorkflowTlsTests','ConsumerTests','ConsumerIceTests')) {
  $source = Join-Path "$root\tests" "$name.cs"
  if (-not (Test-Path -LiteralPath $source)) { continue }
  & $csc /nologo /codepage:65001 /define:WORKFLOW,CONSUMER,READINESS_TEST /target:exe /platform:x64 /optimize+ /debug- /out:"$out\$name.exe" /reference:"$core" /reference:System.Web.Extensions.dll $source $functionalSources
  if ($LASTEXITCODE -ne 0) { throw "$name build failed." }
 }
 & $csc /nologo /codepage:65001 /target:exe /platform:x64 /optimize+ /debug- /out:"$out\ConsumerCoreTests.exe" /reference:"$core" /reference:System.Web.Extensions.dll "$root\tests\ConsumerCoreTests.cs"
 if ($LASTEXITCODE -ne 0) { throw 'Consumer core regression build failed.' }
 & $csc /nologo /codepage:65001 /define:WORKFLOW,CONSUMER /target:exe /platform:x64 /optimize+ /debug- /out:"$out\ConsumerWfpTests.exe" /reference:"$core" /reference:System.Web.Extensions.dll "$root\tests\ReadinessWfpNativeTests.cs" "$root\desktop\ReadinessWfpNative.cs" "$root\desktop\ReadinessWfpShared.cs" "$root\desktop\ReadinessWfpClient.cs" "$root\desktop\ReadinessWfpProcess.cs"
 if ($LASTEXITCODE -ne 0) { throw 'Consumer WFP regression build failed.' }
 if (Test-Path -LiteralPath "$root\tests\ConsumerIceFixture.cs") {
  & $csc /nologo /codepage:65001 /target:exe /platform:x64 /optimize+ /debug- /out:"$out\WorkEnv.Consumer.IceFixture.exe" "$root\tests\ConsumerIceFixture.cs"
  if ($LASTEXITCODE -ne 0) { throw 'Consumer ICE fixture build failed.' }
 }
}
Write-Host 'Consumer candidate built independently.'

[CmdletBinding()]
param(
    [ValidateRange(1, 100)]
    [int]$Count = 1,

    [switch]$FullRace
)

$ErrorActionPreference = "Stop"
$env:CGO_ENABLED = "1"

function Invoke-GoTest {
    param([string[]]$TestArguments)

    & go test @TestArguments
    if ($LASTEXITCODE -ne 0) {
        throw "go test failed with exit code $LASTEXITCODE"
    }
}

$goCompiler = (& go env CC).Trim()
if (-not $goCompiler) {
    throw "Go has no C compiler configured. Install GCC or Clang and set go env CC."
}

Write-Host "CGO compiler: $goCompiler"
Write-Host "Hostile-network repetitions: $Count"

Invoke-GoTest @(
    "-race", "-v", "./internal/client",
    "-run", "Test(Synchronous|Outstanding|QuestionFingerprint|UDPTruncation|PerResolver|InitialAndBackground|BackgroundDiscovery|AutoTransport|PoisonPlus|PoisonSignal|OriginalWinner|ExpiredPoison|ExpiredPath|ResolverPathTimeout|ExplicitTransport|HedgedResponse|JointPathSelection|WarmPath)",
    "-count=$Count"
)

Invoke-GoTest @(
    "-race", "-v", "./internal/udpserver",
    "-run", "TestDynamicNativeQueryAcrossAllTransports",
    "-count=$Count"
)

Invoke-GoTest @(
    "-race", "-v", "./internal/fec",
    "-run", "Test(Survives75PercentLoss|Survives84PercentLoss|LossyNetworkRecoveryEffectiveness|SuperFECParityMeetsRecoveryTarget)",
    "-count=$Count"
)

if ($FullRace) {
    Write-Host "Running the complete repository race suite..."
    Invoke-GoTest @("-race", "./...", "-count=1")
}

Write-Host "Hostile-network test environment passed."

function Test-TcpkGrpcSurface {
<#
.SYNOPSIS
    Enumerate gRPC / Protobuf service surface shipped with the application.

.DESCRIPTION
    Thick clients that use gRPC ship .proto definition files, reference
    Protobuf assemblies, and may enable gRPC server reflection (which lets
    any client enumerate services and methods at runtime without .proto
    files).  This scanner detects:

      1. Shipped .proto files -- attacker can read service contracts,
         message shapes, and internal method names.
      2. gRPC server reflection enabled -- the service exposes a
         ServerReflection endpoint that allows full enumeration.
      3. Service / method definitions parsed from .proto files --
         intelligence for further attack surface mapping.

    Complements Test-TcpkRpcChannels (which checks for insecure
    credentials / cleartext channels).

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $protoFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.proto' -ErrorAction SilentlyContinue)

    foreach ($pf in $protoFiles) {
        $relPath = $pf.FullName
        if ($relPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relPath = $relPath.Substring($root.Length).TrimStart('\')
        }

        New-TcpkFinding -Module 'static' -RuleId 'grpc.proto-shipped' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title "Protobuf definition shipped: $relPath" `
            -File $pf.FullName `
            -Evidence "file=$($pf.Name); size=$($pf.Length)" `
            -Cwe @('CWE-200') `
            -Description ('A .proto (Protocol Buffers) definition file is shipped with the ' +
                'application. It exposes service contracts, RPC method names, and message ' +
                'field types that an attacker can use for targeted API abuse.') `
            -Fix 'Strip .proto files from production builds; they are only needed at compile time.'

        try { $raw = Get-Content -LiteralPath $pf.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }

        $svcRx = [regex]'(?m)^\s*service\s+(\w+)\s*\{'
        $rpcRx = [regex]'(?m)^\s*rpc\s+(\w+)\s*\('

        foreach ($sm in $svcRx.Matches($raw)) {
            $svcName = $sm.Groups[1].Value
            $methods = @($rpcRx.Matches($raw) | ForEach-Object { $_.Groups[1].Value })
            $ev = "service $svcName"
            if ($methods.Count -gt 0) {
                $ev += "; methods: $(($methods | Select-Object -First 10) -join ', ')"
                if ($methods.Count -gt 10) { $ev += " (+$($methods.Count - 10) more)" }
            }

            New-TcpkFinding -Module 'static' -RuleId 'grpc.service-exposed' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "gRPC service defined: ${svcName} ($($methods.Count) methods)" `
                -File $pf.FullName `
                -Evidence $ev.Substring(0, [Math]::Min(200, $ev.Length)) `
                -Cwe @('CWE-200') `
                -Description ('A gRPC service definition exposes method signatures and message ' +
                    'types. An attacker can craft targeted requests, fuzz specific methods, or ' +
                    'identify privileged operations (admin, delete, create).') `
                -Fix 'Ensure all gRPC methods enforce authentication and authorization; apply rate limiting.'
        }
    }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if ($pe.Name -match '(?i)^(grpc|google\.protobuf)') { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        if ($text -match '(?i)ServerReflection|ReflectionServiceImpl|AddGrpcReflection|ServerServiceDefinition.*Reflection') {
            New-TcpkFinding -Module 'static' -RuleId 'grpc.reflection-enabled' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "gRPC server reflection enabled in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence 'references ServerReflection / AddGrpcReflection' `
                -Cwe @('CWE-200') `
                -Description ('The application enables gRPC server reflection, which allows any ' +
                    'client to enumerate all registered services and methods at runtime without ' +
                    'needing .proto files. This is equivalent to leaving WSDL/Swagger exposed ' +
                    'in production.') `
                -Fix 'Disable gRPC reflection in production builds (remove AddGrpcReflection from the service pipeline).'
        }
    }

    $configExts = @('.json', '.config', '.xml', '.yaml', '.yml')
    $configFiles = if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in $configExts -and $_.Length -lt 2MB }
    } else { @() }

    foreach ($cf in $configFiles) {
        try { $raw = Get-Content -LiteralPath $cf.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }
        if ($raw -match '(?i)(ServerReflection|grpc\.reflection|EnableReflection|AddGrpcReflection)') {
            New-TcpkFinding -Module 'static' -RuleId 'grpc.reflection-enabled' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "gRPC reflection reference in config: $($cf.Name)" `
                -File $cf.FullName `
                -Evidence $matches[0] `
                -Cwe @('CWE-200') `
                -Description ('A configuration file references gRPC server reflection, indicating ' +
                    'the service may expose a reflection endpoint for runtime enumeration.') `
                -Fix 'Remove gRPC reflection configuration from production builds.'
        }
    }
}

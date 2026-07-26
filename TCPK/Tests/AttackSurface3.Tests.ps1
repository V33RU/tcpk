BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

Describe 'GrpcSurface' {
    It 'flags a shipped .proto file' {
        $dir = Join-Path $env:TEMP "tcpk-grpc-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $proto = @'
syntax = "proto3";
package myapp;
service UserService {
  rpc GetUser (GetUserRequest) returns (UserResponse);
  rpc DeleteUser (DeleteUserRequest) returns (Empty);
}
message GetUserRequest { string id = 1; }
message UserResponse { string name = 1; }
message DeleteUserRequest { string id = 1; }
message Empty {}
'@
            Set-Content "$dir\user.proto" $proto -Encoding ASCII
            $r = @(Test-TcpkGrpcSurface -Path $dir)
            $shipped = $r | Where-Object { $_.RuleId -eq 'grpc.proto-shipped' }
            $shipped | Should -Not -BeNullOrEmpty
            $svc = $r | Where-Object { $_.RuleId -eq 'grpc.service-exposed' }
            $svc | Should -Not -BeNullOrEmpty
            $svc.Title | Should -Match 'UserService'
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags gRPC reflection in a config file' {
        $dir = Join-Path $env:TEMP "tcpk-grpc-refl-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Set-Content "$dir\appsettings.json" '{"Grpc":{"EnableReflection":true}}' -Encoding ASCII
            $r = @(Test-TcpkGrpcSurface -Path $dir)
            $refl = $r | Where-Object { $_.RuleId -eq 'grpc.reflection-enabled' }
            $refl | Should -Not -BeNullOrEmpty
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns nothing for a directory without gRPC artifacts' {
        $dir = Join-Path $env:TEMP "tcpk-grpc-empty-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Set-Content "$dir\readme.txt" 'hello' -Encoding ASCII
            $r = @(Test-TcpkGrpcSurface -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }
}

Describe 'Wv2Sideload' {
    It 'runs without error on a non-WebView2 directory' {
        $dir = Join-Path $env:TEMP "tcpk-wv2sl-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Set-Content "$dir\readme.txt" 'hello' -Encoding ASCII
            $r = @(Test-TcpkWv2Sideload -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }

    It 'detects WebView2 usage via marker DLL' {
        $dir = Join-Path $env:TEMP "tcpk-wv2sl2-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            New-Item "$dir\WebView2Loader.dll" -ItemType File -Force | Out-Null
            New-Item "$dir\myapp.exe" -ItemType File -Force | Out-Null
            { Test-TcpkWv2Sideload -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'AmsiSurface' {
    It 'runs without error on PEs without AMSI' {
        $dir = Join-Path $env:TEMP "tcpk-amsi-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            { Test-TcpkAmsiSurface -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns nothing for an empty directory' {
        $dir = Join-Path $env:TEMP "tcpk-amsi-empty-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $r = @(Test-TcpkAmsiSurface -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }

    It 'emits amsi rule IDs when findings exist' {
        $dir = Join-Path $env:TEMP "tcpk-amsi-rid-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            $r = @(Test-TcpkAmsiSurface -Path $dir)
            foreach ($f in $r) {
                $f.RuleId | Should -Match '^amsi\.'
            }
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'HollowingApis' {
    It 'runs without error on a PE' {
        $dir = Join-Path $env:TEMP "tcpk-hollow-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            { Test-TcpkHollowingApis -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns nothing for an empty directory' {
        $dir = Join-Path $env:TEMP "tcpk-hollow-empty-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $r = @(Test-TcpkHollowingApis -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }

    It 'emits injection rule IDs when findings exist' {
        $dir = Join-Path $env:TEMP "tcpk-hollow-rid-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            $r = @(Test-TcpkHollowingApis -Path $dir)
            foreach ($f in $r) {
                $f.RuleId | Should -Match '^injection\.'
            }
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'ATT&CK mappings for Tier 2 detections' {
    It 'maps gRPC proto to T1046' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'grpc.proto-shipped' }
        $t | Should -Contain 'T1046 Network Service Discovery'
    }
    It 'maps gRPC reflection to T1046' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'grpc.reflection-enabled' }
        $t | Should -Contain 'T1046 Network Service Discovery'
    }
    It 'maps WebView2 sideload to T1574.002' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'wv2.sideload-surface' }
        $t | Should -Contain 'T1574.002 DLL Side-Loading'
    }
    It 'maps AMSI to T1562.001' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'amsi.init-surface' }
        $t | Should -Contain 'T1562.001 Disable or Modify Tools'
    }
    It 'maps hollowing to T1055.012' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'injection.hollowing-apis' }
        $t | Should -Contain 'T1055.012 Process Hollowing'
    }
    It 'maps DLL injection to T1055' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'injection.dll-inject-apis' }
        $t | Should -Contain 'T1055 Process Injection'
    }
}

Describe 'TASVS mappings for Tier 2 detections' {
    It 'maps gRPC to TASVS-NETWORK' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'grpc.proto-shipped' }
        ($t -join ';') | Should -Match 'TASVS-NETWORK'
    }
    It 'maps WebView2 sideload to TASVS-PLATFORM' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'wv2.sideload-surface' }
        ($t -join ';') | Should -Match 'TASVS-PLATFORM'
    }
    It 'maps AMSI to TASVS-RESILIENCE' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'amsi.init-surface' }
        ($t -join ';') | Should -Match 'TASVS-RESILIENCE'
    }
    It 'maps injection to TASVS-CODE' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'injection.hollowing-apis' }
        ($t -join ';') | Should -Match 'TASVS-CODE'
    }
}

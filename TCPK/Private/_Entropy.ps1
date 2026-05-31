# Entropy + encoding helpers shared by secret/key hunters.

# Shannon entropy in bits-per-character. Random base64 ~5.5-6.0, random hex
# ~3.9-4.0, English prose ~3.5-4.5, a repeated/structured string is much lower.
function Get-TcpkShannonEntropy {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
    $len  = $Text.Length
    $freq = @{}
    foreach ($ch in $Text.ToCharArray()) {
        if ($freq.ContainsKey($ch)) { $freq[$ch]++ } else { $freq[$ch] = 1 }
    }
    $h = 0.0
    foreach ($c in $freq.Values) {
        $p = $c / $len
        $h -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($h, 3)
}

# base64url -> bytes (JWT segments). Returns $null on failure.
function Convert-TcpkFromB64Url {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Text)
    try {
        $s = $Text.Replace('-', '+').Replace('_', '/')
        switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { return $null } }
        return [Convert]::FromBase64String($s)
    } catch { return $null }
}

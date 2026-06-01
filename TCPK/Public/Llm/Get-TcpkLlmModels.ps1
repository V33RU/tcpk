function Get-TcpkLlmModels {
<#
.SYNOPSIS
    List the model IDs the configured provider + key can actually use (live).

.DESCRIPTION
    Queries the provider's models endpoint so you never have to guess a model
    string:
      * anthropic  -> GET {baseUrl}/v1/models
      * openai-dialect (ollama/openai/deepseek/custom) -> GET {baseUrl}/models
    Returns the sorted list of model id strings. Requires the cloud gate +
    a key for cloud providers (the GUI enables this when you pick one). The
    call is metadata-only, so it does not meaningfully bill.

.OUTPUTS
    [string[]] model ids
#>
    [CmdletBinding()]
    param()

    $b = Resolve-TcpkLlmBackend
    $uri = if ($b.Dialect -eq 'anthropic') { "$($b.BaseUrl)/v1/models" } else { "$($b.BaseUrl)/models" }

    $resp = Invoke-RestMethod -Uri $uri -Headers $b.Headers -TimeoutSec 20 -ErrorAction Stop
    # both dialects return { data: [ { id: ... }, ... ] }
    $ids = @($resp.data | ForEach-Object { $_.id }) | Where-Object { $_ }
    return @($ids | Sort-Object -Unique)
}

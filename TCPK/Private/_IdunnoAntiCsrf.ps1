# Idunno.AntiCsrf (CVE-2026-131914, Mandiant MNDT-2026-0048).
#
# Idunno.AntiCsrf is an abandoned ASP.NET WebForms anti-CSRF IHttpModule (last release
# 0.9.1 Beta, 2008). Per the advisory, AntiCsrfModule.PreRequestHandlerExecute calls
# new ObjectStateFormatter().Deserialize(Request.Form[<field>]) on POSTs to ASP.NET pages.
# The parameterless ObjectStateFormatter does no MAC, signature or machineKey check.
#
# Three things are measured, each on its own:
#   identity  the DLL's SHA-256 is one of the three builds the advisory publishes
#   sink      in a handler that IHttpModule.Init of Idunno.AntiCsrf.AntiCsrfModule
#             subscribes (or a method such a handler calls directly), the IL calls
#             Deserialize on a receiver traced only to a parameterless ObjectStateFormatter,
#             every origin of the argument is Request.Form[...] or Request[...], and every
#             call before it on that path is a plain read of the kind the advisory's flow
#             makes ($script:TcpkIdunnoBenign: request / cookie / string / attribute /
#             settings reads, or a method of the assembly that only makes those). Anything
#             else (a crypto call, a verify-style name, a call handed request input, an
#             unknown call, another entry shape) keeps a recompiled build a lead.
#   loaded    the module's registration for the DLL's application: applicationHost.config,
#             then the in-scan parent web.configs, then the application's own web.config,
#             applying add / remove / clear in that order, following configSource
#
# Rules:
#   deser.idunno-anticsrf-module  CRITICAL Confirmed / Confirmed (IL): identity or sink
#                                 proven, DLL in <app>\bin\, registered by the
#                                 application's own web.config.
#                                 HIGH Inferred: a registration applies but something is
#                                 unproven (sink not proven, the folder is not an application
#                                 per applicationHost.config, registration only inherited or
#                                 from applicationHost.config, only below the application
#                                 level, or httpModules-only with Integrated validation off
#                                 or unreadable at the level that applies).
#   deser.idunno-anticsrf-dll     HIGH Inferred: sink proven or unverified, no registration
#                                 for its application, or the DLL is not in a bin\ folder.
#                                 INFO Likely-FP (IL): IL read, no Deserialize on a state
#                                 formatter at all.
#   deser.idunno-anticsrf-config  HIGH Inferred: a config registers the module and no
#                                 scanned DLL's application picks it up.

# SHA-256 of the public 0.9.1.0 builds, copied from the advisory's hash table.
$script:TcpkIdunnoAntiCsrfBuilds = @{
    'da1efcfed182597ee946a9ef2895dfdfeab2bdff16855aeef01656d8158ead06' = '0.9.1.0 official 2008 release build'
    'c5c994891783453ae85f3ef8efb48592b7c560aeb56f531ee9ea5736518246eb' = 'rebuild of the CodePlex 0.9.1 Beta source, Release'
    'aa7bbad4a7ebc38519955ac65517716569508ee4f61fc2f1276086940501e9bf' = 'rebuild of the CodePlex 0.9.1 Beta source, Debug'
}

$script:TcpkIdunnoAntiCsrfCve      = 'CVE-2026-131914'
$script:TcpkIdunnoAntiCsrfAdvisory = 'https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md'
# Base vector from the advisory (its published vector adds E:A, which does not change 9.3).
$script:TcpkIdunnoAntiCsrfCvss     = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'

# What the advisory says about the published builds. Always attributed, never stated as a
# measurement of the scanned copy.
$script:TcpkIdunnoAntiCsrfFlow = ('MNDT-2026-0048 describes the published 0.9.1 builds as follows. On a POST to an ASP.NET ' +
    'Page that neither implements ISuppressCsrfCheck nor carries [SuppressCsrfCheck], AntiCsrfModule.PreRequestHandlerExecute ' +
    'checks only that the CSRF cookie and the CSRF form field are non-empty, then calls new ObjectStateFormatter().Deserialize ' +
    'on the form field, before Page_Load. The parameterless ObjectStateFormatter does no MAC, signature or machineKey check. ' +
    'Pipeline-level authentication (AuthenticateRequest / AuthorizeRequest) runs first, so the exposed pages are the .aspx ' +
    'pages reachable without it, including pages that check the session only inside Page_Load. On those, one POST with an ' +
    'ObjectStateFormatter gadget chain in the form field runs code as the IIS worker process (w3wp.exe). The advisory reports ' +
    'exploitation in the wild and no fixed release.')

$script:TcpkIdunnoAntiCsrfScope = 'MNDT-2026-0048 covers 0.9.1.0 / 0.9.1 Beta, the three published builds and recompiled or customised builds of that source.'

$script:TcpkIdunnoAntiCsrfFixRemove = ('Remove every <add> of Idunno.AntiCsrf.AntiCsrfModule from <httpModules> and <modules> ' +
    '(and from applicationHost.config if it is registered there), remove the csrfSettings <section> declaration and the ' +
    '<csrfSettings> element, drop code that references ISuppressCsrfCheck or [SuppressCsrfCheck], and delete ' +
    'Idunno.AntiCsrf.dll from bin\. Replace it with a supported anti-CSRF control, such as System.Web.Helpers.AntiForgery ' +
    '(AntiForgery.GetHtml / AntiForgery.Validate) or Page.ViewStateUserKey with MAC-validated ViewState.')

$script:TcpkIdunnoAntiCsrfFixAssess = ('Then review the IIS logs for POST requests to .aspx pages answered with HTTP 302 or 500 ' +
    'and unusually large request sizes (cs-bytes, where logged). Where there is evidence of exploitation, rotate every secret ' +
    'in web.config and applicationHost.config (machineKey keys, encryption keys, database credentials) and inspect the ' +
    'webroot for unauthorized files. Ref: ' + $script:TcpkIdunnoAntiCsrfAdvisory)

$script:TcpkIdunnoAntiCsrfFixClean = ('Read AntiCsrfModule.PreRequestHandlerExecute in a decompiler to see how this build ' +
    'validates the token. If it derives from the 0.9.1 source, replace it with a supported anti-CSRF control as ' +
    'MNDT-2026-0048 recommends. Ref: ' + $script:TcpkIdunnoAntiCsrfAdvisory)

# Declaring types whose Deserialize the IL check looks at.
$script:TcpkIdunnoStateFormatters = @{
    'System.Web.UI.ObjectStateFormatter'      = 'ObjectStateFormatter'
    'System.Web.UI.IStateFormatter'           = 'IStateFormatter'
    'System.Runtime.Serialization.IFormatter' = 'IFormatter'
    'System.Web.UI.LosFormatter'              = 'LosFormatter'
}

# A call before Deserialize whose name looks like a token check. A modified build that gates
# the value this way is not proven by the IL walk, so the sink stays a lead.
$script:TcpkIdunnoGateRx = '(?i)(verify|validat|signature|hmac|checkmac|unprotect|decrypt|^mac|mac$)'

# The calls the advisory's flow makes before the sink: request, cookie, string, attribute,
# settings and event-wiring reads, error redirects and exception construction, plus string
# building and trace output (none of them can check a token against a secret). For a build
# whose hash is not published, the sink is proven only when every call before it on its path
# is one of these (or a method of the assembly whose body only makes these). Anything else
# might be a token check TCPK cannot see through, so the build stays a lead.
$script:TcpkIdunnoBenign = @(
    @{ T = '^System\.Web\.HttpApplication$';                                 M = '^(get_|add_)' }
    @{ T = '^System\.Web\.(HttpContext|HttpContextBase)$';                   M = '^get_' }
    @{ T = '^System\.Web\.(HttpRequest|HttpRequestBase)$';                   M = '^get_' }
    @{ T = '^System\.Web\.(HttpResponse|HttpResponseBase)$';                 M = '^(get_|Redirect$|End$|Clear$|set_StatusCode$)' }
    @{ T = '^System\.Web\.HttpCookieCollection$';                            M = '^(get_Item|Get)$' }
    @{ T = '^System\.Web\.HttpCookie$';                                      M = '^(get_|set_|\.ctor$)' }
    @{ T = '^System\.Collections\.Specialized\.NameValueCollection$';       M = '^(get_Item|Get)$' }
    @{ T = '^System\.String$';                                                M = '^(IsNullOrEmpty|IsNullOrWhiteSpace|Equals|op_Equality|op_Inequality|Compare|CompareOrdinal|get_Length|get_Chars|Concat|Format|Join|Substring|ToString|Trim|TrimStart|TrimEnd|ToLower|ToLowerInvariant|ToUpper|ToUpperInvariant|Replace|Contains|StartsWith|EndsWith|IndexOf|Split)$' }
    @{ T = '^System\.Object$';                                                M = '^(GetType|\.ctor|Equals|ToString)$' }
    @{ T = '^System\.IFormattable$';                                          M = '^ToString$' }
    @{ T = '^System\.Text\.StringBuilder$';                                   M = '^(\.ctor|Append|AppendLine|AppendFormat|ToString|get_Length)$' }
    @{ T = '^System\.Runtime\.CompilerServices\.DefaultInterpolatedStringHandler$'; M = '.' }
    @{ T = '^System\.Diagnostics\.(Trace|Debug)$';                            M = '^(Write|WriteLine|WriteIf|WriteLineIf|TraceInformation|TraceWarning|TraceError|Assert)$' }
    @{ T = '^System\.Web\.TraceContext$';                                     M = '^(Write|Warn)$' }
    @{ T = '^System\.Type$';                                                  M = '^(GetTypeFromHandle|op_Equality|op_Inequality|IsAssignableFrom|IsInstanceOfType|get_\w+)$' }
    @{ T = '^System\.(Attribute|Reflection\.MemberInfo|Reflection\.ICustomAttributeProvider)$'; M = '^(IsDefined|GetCustomAttribute|GetCustomAttributes|get_Name)$' }
    @{ T = '^System\.EventHandler$';                                          M = '^\.ctor$' }
    @{ T = '^System\.Web\.UI\.(Control|Page|TemplateControl)$';              M = '^(get_|add_)' }
    @{ T = '^System\.Web\.UI\.ObjectStateFormatter$';                        M = '^\.ctor$' }
    @{ T = '^System\.(Configuration\.ConfigurationManager|Web\.Configuration\.WebConfigurationManager)$'; M = '^GetSection$' }
    @{ T = '^System\.Configuration\.ConfigurationElement$';                  M = '^(get_Item|set_Item)$' }
    @{ T = '^System\.Globalization\.CultureInfo$';                           M = '^get_InvariantCulture$' }
    @{ T = '^System\.([\w.]+\.)?\w*Exception$';                               M = '^\.ctor$' }
)

# IL stack effects by StackBehaviour name (Varpush / Varpop are computed from the operand).
$script:TcpkIdunnoIlPush = @{ Push0 = 0; Push1 = 1; Pushi = 1; Pushi8 = 1; Pushr4 = 1; Pushr8 = 1; Pushref = 1; Push1_push1 = 2 }
$script:TcpkIdunnoIlPop  = @{
    Pop0 = 0; Pop1 = 1; Popi = 1; Popref = 1
    Pop1_pop1 = 2; Popi_pop1 = 2; Popi_popi = 2; Popi_popi8 = 2; Popi_popr4 = 2; Popi_popr8 = 2; Popref_pop1 = 2; Popref_popi = 2
    Popi_popi_popi = 3; Popref_popi_popi = 3; Popref_popi_popi8 = 3; Popref_popi_popr4 = 3; Popref_popi_popr8 = 3; Popref_popi_popref = 3
}

# Cheap pre-filter for Test-TcpkDeserialization's PE loop: the file name, or the assembly /
# namespace name in the metadata string heap (a renamed copy still carries it).
function Test-TcpkIdunnoAntiCsrfCandidate {
    param([Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Text = '')
    if ($Name -ieq 'Idunno.AntiCsrf.dll') { return $true }
    return ($Text -and $Text.Contains('Idunno.AntiCsrf'))
}

# ---------------------------------------------------------------------------------------
# IL
# ---------------------------------------------------------------------------------------

# @(pops, pushes) of one instruction, or $null when it is not known here (calli, ret, ...).
function Get-TcpkIdunnoStackEffect {
    param($Ins)
    $op = $Ins.OpCode
    $mref = $Ins.Operand -as [Mono.Cecil.MethodReference]
    $pushName = "$($op.StackBehaviourPush)"
    $popName  = "$($op.StackBehaviourPop)"
    if ($script:TcpkIdunnoIlPush.ContainsKey($pushName)) { $push = $script:TcpkIdunnoIlPush[$pushName] }
    elseif ($pushName -eq 'Varpush' -and $mref) {
        # An init accessor returns 'void modreq(IsExternalInit)': unwrap modifiers before the
        # void test. Only modifiers: a void* return is a value.
        $rt = $mref.ReturnType
        while ($rt -is [Mono.Cecil.IModifierType]) { $rt = $rt.ElementType }
        $push = $(if ($rt.MetadataType -eq [Mono.Cecil.MetadataType]::Void) { 0 } else { 1 })
    }
    else { return $null }
    if ($script:TcpkIdunnoIlPop.ContainsKey($popName)) { $pop = $script:TcpkIdunnoIlPop[$popName] }
    elseif ($popName -eq 'Varpop' -and $mref) {
        $pop = $mref.Parameters.Count
        if ("$($op.Code)" -ne 'Newobj' -and $mref.HasThis -and -not $mref.ExplicitThis) { $pop++ }
    }
    else { return $null }
    return @($pop, $push)
}

# Offsets where straight-line stack tracking must stop: branch targets and the starts of
# try / handler / filter blocks. Cached per method.
function Get-TcpkIdunnoStarts {
    param($Method, $Ctx)
    $key = "$($Method.MetadataToken.ToInt32())"
    # The comma keeps PowerShell from unrolling the set (an empty one would come back as $null).
    if ($Ctx.Starts.ContainsKey($key)) { return ,$Ctx.Starts[$key] }
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    foreach ($ins in $Method.Body.Instructions) {
        if ($ins.Operand -is [Mono.Cecil.Cil.Instruction]) { [void]$set.Add($ins.Operand.Offset) }
        elseif ($ins.Operand -is [Mono.Cecil.Cil.Instruction[]]) { foreach ($x in $ins.Operand) { [void]$set.Add($x.Offset) } }
    }
    if ($Method.Body.HasExceptionHandlers) {
        foreach ($h in $Method.Body.ExceptionHandlers) {
            foreach ($x in @($h.TryStart, $h.HandlerStart, $h.FilterStart)) { if ($x) { [void]$set.Add($x.Offset) } }
        }
    }
    $Ctx.Starts[$key] = $set
    return ,$set
}

# The instruction that pushed the value $Depth slots below the top of the stack as it
# stands just before $Ins runs (Depth 0 is the top). Straight-line only: $null at a branch
# target, a block start, after an unconditional transfer, or on an unknown stack effect.
function Find-TcpkIdunnoProducer {
    param($Ins, [int]$Depth, $Method, $Ctx)
    $starts = Get-TcpkIdunnoStarts -Method $Method -Ctx $Ctx
    $cur = $Ins
    $d = $Depth
    for ($guard = 0; $guard -lt 512; $guard++) {
        if ($starts.Contains($cur.Offset)) { return $null }
        $j = $cur.Previous
        if ($null -eq $j) { return $null }
        if (@('Branch', 'Return', 'Throw') -contains "$($j.OpCode.FlowControl)") { return $null }
        $eff = Get-TcpkIdunnoStackEffect -Ins $j
        if ($null -eq $eff) { return $null }
        if ($d -lt $eff[1]) {
            if ("$($j.OpCode.Code)" -eq 'Dup') { return (Find-TcpkIdunnoProducer -Ins $j -Depth 0 -Method $Method -Ctx $Ctx) }
            return $j
        }
        $d = $d - $eff[1] + $eff[0]
        $cur = $j
    }
    return $null
}

function Get-TcpkIdunnoLocalIndex {
    param($Ins, [ValidateSet('ld', 'st')][string]$Kind)
    $code = "$($Ins.OpCode.Code)"
    if ($code -match "^${Kind}loc_([0-3])$") { return [int]$Matches[1] }
    if ($code -ieq "${Kind}loc_S" -or $code -ieq "${Kind}loc") {
        $v = $Ins.Operand -as [Mono.Cecil.Cil.VariableDefinition]
        if ($v) { return $v.Index }
    }
    return -1
}

# Field writes in the whole assembly, by field FullName: stfld / stsfld, and ldflda / ldsflda
# (an address taken is a write this walk cannot follow). Built once per assembly.
function Get-TcpkIdunnoFieldStores {
    param($Ctx)
    if ($null -ne $Ctx.FieldStores) { return $Ctx.FieldStores }
    $map = @{}
    foreach ($t in @($Ctx.Module.GetTypes())) {
        foreach ($m in @($t.Methods)) {
            if (-not $m.HasBody) { continue }
            foreach ($ins in $m.Body.Instructions) {
                $c = "$($ins.OpCode.Code)"
                $byRef = ($c -eq 'Ldflda' -or $c -eq 'Ldsflda')
                if (-not $byRef -and $c -ne 'Stfld' -and $c -ne 'Stsfld') { continue }
                $fr = $ins.Operand -as [Mono.Cecil.FieldReference]
                if (-not $fr) { continue }
                $k = "$($fr.FullName)"
                if (-not $map.ContainsKey($k)) { $map[$k] = New-Object 'System.Collections.Generic.List[object]' }
                $map[$k].Add([pscustomobject]@{ Ins = $ins; Method = $m; ByRef = $byRef })
            }
        }
    }
    $Ctx.FieldStores = $map
    return $map
}

# stloc sites per local index, and the locals whose address is taken (ldloca), for one
# method. Cached per method so a walk does not rescan the body for every load.
function Get-TcpkIdunnoLocalStores {
    param($Method, $Ctx)
    $key = "$($Method.MetadataToken.ToInt32())"
    if ($Ctx.LocalStores.ContainsKey($key)) { return $Ctx.LocalStores[$key] }
    $map = @{ Stores = @{}; ByRef = (New-Object 'System.Collections.Generic.HashSet[int]') }
    foreach ($s in $Method.Body.Instructions) {
        $i = Get-TcpkIdunnoLocalIndex -Ins $s -Kind 'st'
        if ($i -ge 0) {
            if (-not $map.Stores.ContainsKey($i)) { $map.Stores[$i] = New-Object 'System.Collections.Generic.List[object]' }
            $map.Stores[$i].Add($s)
            continue
        }
        if ("$($s.OpCode.Code)" -match '^Ldloca') {
            $v = $s.Operand -as [Mono.Cecil.Cil.VariableDefinition]
            if ($v) { [void]$map.ByRef.Add($v.Index) }
        }
    }
    $Ctx.LocalStores[$key] = $map
    return $map
}

# Where a stack value came from: follows dup, castclass / isinst, a local's stores in the
# same method and a field's stores in the assembly. Returns a list of @{ Ins; Method }
# origins; a $null entry means one path could not be traced (including a ref / out write
# through ldloca or ldflda). Each local and field is expanded once per walk ($Seen), so a
# method with many stores, or a cycle between locals, stays linear.
function Get-TcpkIdunnoOrigins {
    param($Producer, $Method, $Ctx, [int]$Hops = 0, $Seen = $null)
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Seen) { $Seen = New-Object 'System.Collections.Generic.HashSet[string]' }
    if ($null -eq $Producer -or $Hops -gt 6) { $out.Add($null); return ,$out }
    $code = "$($Producer.OpCode.Code)"

    $li = Get-TcpkIdunnoLocalIndex -Ins $Producer -Kind 'ld'
    if ($li -ge 0) {
        if (-not $Seen.Add("L:$($Method.MetadataToken.ToInt32()):$li")) { return ,$out }
        $ls = Get-TcpkIdunnoLocalStores -Method $Method -Ctx $Ctx
        if ($ls.ByRef.Contains($li)) { $out.Add($null) }
        if (-not $ls.Stores.ContainsKey($li)) { $out.Add($null); return ,$out }
        foreach ($s in $ls.Stores[$li]) {
            $p = Find-TcpkIdunnoProducer -Ins $s -Depth 0 -Method $Method -Ctx $Ctx
            foreach ($o in (Get-TcpkIdunnoOrigins -Producer $p -Method $Method -Ctx $Ctx -Hops ($Hops + 1) -Seen $Seen)) { $out.Add($o) }
        }
        return ,$out
    }
    if ($code -eq 'Ldfld' -or $code -eq 'Ldsfld') {
        $fr = $Producer.Operand -as [Mono.Cecil.FieldReference]
        if (-not $fr) { $out.Add($null); return ,$out }
        if (-not $Seen.Add("F:$($fr.FullName)")) { return ,$out }
        $stores = (Get-TcpkIdunnoFieldStores -Ctx $Ctx)["$($fr.FullName)"]
        if (-not $stores) { $out.Add($null); return ,$out }
        foreach ($st in $stores) {
            if ($st.ByRef) { $out.Add($null); continue }
            $p = Find-TcpkIdunnoProducer -Ins $st.Ins -Depth 0 -Method $st.Method -Ctx $Ctx
            foreach ($o in (Get-TcpkIdunnoOrigins -Producer $p -Method $st.Method -Ctx $Ctx -Hops ($Hops + 1) -Seen $Seen)) { $out.Add($o) }
        }
        return ,$out
    }
    if ($code -eq 'Castclass' -or $code -eq 'Isinst') {
        $p = Find-TcpkIdunnoProducer -Ins $Producer -Depth 0 -Method $Method -Ctx $Ctx
        foreach ($o in (Get-TcpkIdunnoOrigins -Producer $p -Method $Method -Ctx $Ctx -Hops ($Hops + 1) -Seen $Seen)) { $out.Add($o) }
        return ,$out
    }
    $out.Add([pscustomobject]@{ Ins = $Producer; Method = $Method })
    return ,$out
}

# A call that looks like a token check: crypto or machineKey work (HMAC construction,
# ComputeHash, MachineKey.Unprotect...), or a method whose name reads as verify / validate /
# MAC. Returns its label, or '' when the instruction is not one.
function Get-TcpkIdunnoGateLabel {
    param($Ins)
    $c = "$($Ins.OpCode.Code)"
    if ($c -ne 'Call' -and $c -ne 'Callvirt' -and $c -ne 'Newobj') { return '' }
    $gm = $Ins.Operand -as [Mono.Cecil.MethodReference]
    if (-not $gm) { return '' }
    $gd = "$($gm.DeclaringType.FullName)"
    if ($gd -eq 'System.Web.HttpRequest' -or $gd -eq 'System.Web.HttpRequestBase') { return '' }
    $label = "$($gm.DeclaringType.Name)::$($gm.Name)"
    if ($gd -like 'System.Security.Cryptography.*' -or $gd -eq 'System.Web.Security.MachineKey') { return $label }
    if ($c -ne 'Newobj' -and "$($gm.Name)" -match $script:TcpkIdunnoGateRx) { return $label }
    return ''
}

# A call or constructor that is handed request input before the sink, such as
# IsValid(formValue, mac), new CsrfToken(formValue, tag) or CheckToken(Request.Form[...]): whatever it does with the value, TCPK cannot tell it is not a
# token check. String / NameValueCollection / HttpRequest members (IsNullOrEmpty, get_Item)
# are not counted. Returns its label, or ''.
function Get-TcpkIdunnoInputGateLabel {
    param($Ins, $Method, $Ctx)
    $c = "$($Ins.OpCode.Code)"
    if ($c -ne 'Call' -and $c -ne 'Callvirt' -and $c -ne 'Newobj') { return '' }
    $gm = $Ins.Operand -as [Mono.Cecil.MethodReference]
    if (-not $gm -or $gm.Parameters.Count -eq 0) { return '' }
    if (@('System.String', 'System.Collections.Specialized.NameValueCollection', 'System.Web.HttpRequest', 'System.Web.HttpRequestBase') -contains "$($gm.DeclaringType.FullName)") { return '' }
    for ($pi = 0; $pi -lt $gm.Parameters.Count; $pi++) {
        $ap = Find-TcpkIdunnoProducer -Ins $Ins -Depth $pi -Method $Method -Ctx $Ctx
        foreach ($ao in (Get-TcpkIdunnoOrigins -Producer $ap -Method $Method -Ctx $Ctx)) {
            if (Get-TcpkIdunnoRequestSource -Origin $ao -Ctx $Ctx) { return "$($gm.DeclaringType.Name)::$($gm.Name)" }
        }
    }
    return ''
}

# A method of this assembly that a call names: the definition itself, or the definition behind
# a generic instance (Foo<string>(), Bar<string>::Foo()). $null for anything outside the
# assembly (the resolver is never asked about System.Web or the BCL).
function Resolve-TcpkIdunnoLocalMethod {
    param($MRef)
    if (-not $MRef) { return $null }
    $md = $MRef -as [Mono.Cecil.MethodDefinition]
    if ($md) { return $md }
    $et = $null
    try { $et = $MRef.DeclaringType.GetElementType() } catch { }
    if (-not ($et -is [Mono.Cecil.TypeDefinition])) { return $null }
    try { return $MRef.Resolve() } catch { return $null }
}

# '' when the instruction is not a call, or is a call the advisory's flow makes (the table
# above, or a method of this assembly whose body only makes such calls). Otherwise a label
# naming it: a token-check call (crypto / machineKey, a verify-style name, a call handed
# request input) or any other call TCPK does not treat as a plain read.
function Get-TcpkIdunnoBlocker {
    param($Ins, $Method, $Ctx, [int]$Depth = 0)
    $c = "$($Ins.OpCode.Code)"
    if (@('Call', 'Callvirt', 'Newobj', 'Calli') -notcontains $c) { return '' }
    if ($c -eq 'Calli') { return 'calli (indirect call)' }
    $g = Get-TcpkIdunnoGateLabel $Ins
    if ($g) { return $g }
    $g = Get-TcpkIdunnoInputGateLabel -Ins $Ins -Method $Method -Ctx $Ctx
    if ($g) { return $g }
    $mr = $Ins.Operand -as [Mono.Cecil.MethodReference]
    if (-not $mr) { return 'unknown call' }
    $label = "$($mr.DeclaringType.Name)::$($mr.Name)"
    $md = Resolve-TcpkIdunnoLocalMethod $mr
    if ($md) {
        if (Test-TcpkIdunnoBenignBody -Method $md -Ctx $Ctx -Depth ($Depth + 1)) { return '' }
        return $label
    }
    $decl = ''
    try { $decl = "$($mr.DeclaringType.GetElementType().FullName)" } catch { $decl = "$($mr.DeclaringType.FullName)" }
    foreach ($b in $script:TcpkIdunnoBenign) { if ($decl -match $b.T -and "$($mr.Name)" -match $b.M) { return '' } }
    return $label
}

# True when a method of this assembly only makes calls the advisory's flow makes. Cached per
# assembly; a method seen again while it is being checked (recursion) counts as not benign.
function Test-TcpkIdunnoBenignBody {
    param($Method, $Ctx, [int]$Depth)
    $k = "$($Method.FullName)"
    if ($Ctx.Benign.ContainsKey($k)) { return $Ctx.Benign[$k] }
    $Ctx.Benign[$k] = $false
    if ($Depth -gt 4 -or -not $Method.HasBody) { return $false }
    if ("$($Method.Name)" -match $script:TcpkIdunnoGateRx) { return $false }
    foreach ($ins in $Method.Body.Instructions) {
        if (Get-TcpkIdunnoBlocker -Ins $ins -Method $Method -Ctx $Ctx -Depth $Depth) { return $false }
    }
    $Ctx.Benign[$k] = $true
    return $true
}

# The module's entry: Idunno.AntiCsrf.AntiCsrfModule (the only type the registrations name),
# the method an IHttpModule.Init call runs on it, and the handlers that Init subscribes
# (ldftn / ldvirtftn in Init or in a method of this assembly Init calls directly). ASP.NET runs
# a module only through IHttpModule.Init. Init is the type's explicit IHttpModule::Init
# implementation, else the most derived public instance Init(HttpApplication) in the type or
# its base types in this assembly (so an override wins over the base, and an inherited Init
# counts). An Init of any other interface is not an entry.
function Get-TcpkIdunnoEntry {
    param($Module)
    $out = [pscustomobject]@{ HasModuleType = $false; Init = $null; Handlers = @() }
    $t = $Module.GetType('Idunno.AntiCsrf.AntiCsrfModule')
    if (-not $t) { return $out }
    $out.HasModuleType = $true
    $chain = New-Object 'System.Collections.Generic.List[object]'
    $x = $t
    while ($x -is [Mono.Cecil.TypeDefinition] -and -not $chain.Contains($x)) {
        $chain.Add($x)
        $bt = $x.BaseType
        $x = $null
        if ($bt) { try { $e = $bt.GetElementType(); if ($e -is [Mono.Cecil.TypeDefinition]) { $x = $e } } catch { } }
    }
    $init = $null
    foreach ($y in $chain) {
        foreach ($m in @($y.Methods)) {
            if (@($m.Overrides | Where-Object { "$($_.DeclaringType.FullName)::$($_.Name)" -eq 'System.Web.IHttpModule::Init' }).Count -gt 0) { $init = $m; break }
        }
        if ($init) { break }
    }
    if (-not $init) {
        foreach ($y in $chain) {
            foreach ($m in @($y.Methods)) {
                if ("$($m.Name)" -ceq 'Init' -and -not $m.IsStatic -and $m.IsPublic -and $m.Parameters.Count -eq 1 -and
                    "$($m.Parameters[0].ParameterType.FullName)" -eq 'System.Web.HttpApplication') { $init = $m; break }
            }
            if ($init) { break }
        }
    }
    $out.Init = $init
    if (-not $init -or -not $init.HasBody) { return $out }
    $wirers = New-Object 'System.Collections.Generic.List[object]'
    $wirers.Add($init)
    foreach ($ins in $init.Body.Instructions) {
        if (@('Call', 'Callvirt') -notcontains "$($ins.OpCode.Code)") { continue }
        $md = Resolve-TcpkIdunnoLocalMethod ($ins.Operand -as [Mono.Cecil.MethodReference])
        if ($md -and $md.HasBody -and -not $wirers.Contains($md)) { $wirers.Add($md) }
    }
    $handlers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($w in $wirers) {
        foreach ($ins in $w.Body.Instructions) {
            if (@('Ldftn', 'Ldvirtftn') -notcontains "$($ins.OpCode.Code)") { continue }
            $md = Resolve-TcpkIdunnoLocalMethod ($ins.Operand -as [Mono.Cecil.MethodReference])
            if ($md -and -not $handlers.Contains($md)) { $handlers.Add($md) }
        }
    }
    $out.Handlers = $handlers.ToArray()
    return $out
}

# Whether a method is on the module's request path in the advisory's shape: it is a handler
# Init subscribes, or a handler calls it directly with nothing but plain reads before that
# call. Returns @{ Ok; Why }.
function Get-TcpkIdunnoPath {
    param($Method, $Entry, $Ctx)
    if (-not $Entry.HasModuleType) { return [pscustomobject]@{ Ok = $false; Why = 'the assembly defines no Idunno.AntiCsrf.AntiCsrfModule, the type the registrations name' } }
    if (-not $Entry.Init) { return [pscustomobject]@{ Ok = $false; Why = 'no IHttpModule.Init implementation found on Idunno.AntiCsrf.AntiCsrfModule' } }
    foreach ($h in $Entry.Handlers) { if ($h -eq $Method) { return [pscustomobject]@{ Ok = $true; Why = '' } } }
    $blocked = ''
    foreach ($h in $Entry.Handlers) {
        if (-not $h.HasBody) { continue }
        $before = ''
        foreach ($ins in $h.Body.Instructions) {
            $md = $null
            if (@('Call', 'Callvirt') -contains "$($ins.OpCode.Code)") { $md = Resolve-TcpkIdunnoLocalMethod ($ins.Operand -as [Mono.Cecil.MethodReference]) }
            if ($md -and $md -eq $Method) {
                if (-not $before) { return [pscustomobject]@{ Ok = $true; Why = '' } }
                $blocked = "called from handler $($h.Name) after $before"
                break
            }
            if (-not $before) { $before = Get-TcpkIdunnoBlocker -Ins $ins -Method $h -Ctx $Ctx }
        }
    }
    if ($blocked) { return [pscustomobject]@{ Ok = $false; Why = $blocked } }
    return [pscustomobject]@{ Ok = $false; Why = "not a handler that AntiCsrfModule's IHttpModule.Init subscribes, nor a method such a handler calls directly" }
}

function Test-TcpkIdunnoUnkeyedNew {
    param($Ins)
    if ($null -eq $Ins -or "$($Ins.OpCode.Code)" -ne 'Newobj') { return $false }
    $mref = $Ins.Operand -as [Mono.Cecil.MethodReference]
    return ($mref -and "$($mref.DeclaringType.FullName)" -eq 'System.Web.UI.ObjectStateFormatter' -and $mref.Parameters.Count -eq 0)
}

function Format-TcpkIdunnoIns {
    param($Ins)
    if ($null -eq $Ins) { return '(untraced)' }
    $operand = ''
    $mref = $Ins.Operand -as [Mono.Cecil.MethodReference]
    $fref = $Ins.Operand -as [Mono.Cecil.FieldReference]
    if ($mref) { $operand = " $($mref.DeclaringType.Name)::$($mref.Name)" }
    elseif ($fref) { $operand = " $($fref.DeclaringType.Name)::$($fref.Name)" }
    return ('IL_{0:x4} {1}{2}' -f $Ins.Offset, $Ins.OpCode.Name, $operand)
}

function Format-TcpkIdunnoMethod {
    param($Method)
    $tok = ''
    try { $tok = (' 0x{0:X8}' -f $Method.MetadataToken.ToInt32()) } catch { }
    return "$($Method.DeclaringType.FullName)::$($Method.Name)$tok"
}

# 'Request.Form[...]' / 'Request[...]' when an origin is a read of request input, else ''.
function Get-TcpkIdunnoRequestSource {
    param($Origin, $Ctx)
    if ($null -eq $Origin) { return '' }
    $mref = $Origin.Ins.Operand -as [Mono.Cecil.MethodReference]
    if (-not $mref -or "$($mref.Name)" -ne 'get_Item') { return '' }
    $decl = "$($mref.DeclaringType.FullName)"
    if ($decl -eq 'System.Web.HttpRequest' -or $decl -eq 'System.Web.HttpRequestBase') { return 'Request[...]' }
    if ($decl -ne 'System.Collections.Specialized.NameValueCollection') { return '' }
    $rp = Find-TcpkIdunnoProducer -Ins $Origin.Ins -Depth 1 -Method $Origin.Method -Ctx $Ctx
    foreach ($ro in (Get-TcpkIdunnoOrigins -Producer $rp -Method $Origin.Method -Ctx $Ctx)) {
        if ($null -eq $ro) { continue }
        $rm = $ro.Ins.Operand -as [Mono.Cecil.MethodReference]
        if ($rm -and "$($rm.Name)" -eq 'get_Form' -and @('System.Web.HttpRequest', 'System.Web.HttpRequestBase') -contains "$($rm.DeclaringType.FullName)") {
            return 'Request.Form[...]'
        }
    }
    return ''
}

# One Deserialize site: what its receiver and argument trace to, and whether it is proven.
# Proven needs all of: the method is reached from the module's entry points, the receiver
# traces only to new ObjectStateFormatter(), every origin of the string argument is request
# input, and no token-check call comes before it in the method.
function Get-TcpkIdunnoSinkSite {
    param($Method, $Ins, $MRef, [string]$Kind, $Ctx, [bool]$CtorInMethod, $Path)
    $where = "$(Format-TcpkIdunnoMethod $Method) $(Format-TcpkIdunnoIns $Ins)"
    $code = "$($Ins.OpCode.Code)"
    $site = [pscustomobject]@{ Where = $where; Kind = $Kind; ReceiverOk = $false; Receiver = ''; Source = ''; Gates = @(); Reached = [bool]$Path.Ok; PathWhy = "$($Path.Why)"; Proven = $false }

    if ($code -eq 'Ldftn' -or $code -eq 'Ldvirtftn') {
        if ($Kind -eq 'IFormatter' -and -not $CtorInMethod) { return $null }
        $site.Receiver = 'method-group delegate (ldftn); receiver and argument not traced'
        return $site
    }

    $recv = Find-TcpkIdunnoProducer -Ins $Ins -Depth $MRef.Parameters.Count -Method $Method -Ctx $Ctx
    # A List comes back (return ,$out); keep it as one object, do not wrap it in @().
    $origins = Get-TcpkIdunnoOrigins -Producer $recv -Method $Method -Ctx $Ctx
    $bad = @($origins | Where-Object { $null -eq $_ -or -not (Test-TcpkIdunnoUnkeyedNew $_.Ins) })
    $site.ReceiverOk = ($origins.Count -gt 0 -and $bad.Count -eq 0)
    if ($site.ReceiverOk) {
        $o = $origins[0]
        $site.Receiver = "parameterless ObjectStateFormatter created at $(Format-TcpkIdunnoMethod $o.Method) $(Format-TcpkIdunnoIns $o.Ins)"
    } elseif (@($bad | Where-Object { $null -eq $_ }).Count -gt 0) {
        $site.Receiver = 'receiver not traced (it crosses a branch, a parameter or a store TCPK does not follow)'
    } else {
        $site.Receiver = "receiver comes from $(Format-TcpkIdunnoIns $bad[0].Ins), not from new ObjectStateFormatter()"
    }
    # A BinaryFormatter / SoapFormatter reached through IFormatter is not this CVE.
    if ($Kind -eq 'IFormatter' -and -not $site.ReceiverOk -and -not $CtorInMethod) { return $null }

    if ($MRef.Parameters.Count -eq 1 -and "$($MRef.Parameters[0].ParameterType.FullName)" -eq 'System.String') {
        $arg = Find-TcpkIdunnoProducer -Ins $Ins -Depth 0 -Method $Method -Ctx $Ctx
        $aos = Get-TcpkIdunnoOrigins -Producer $arg -Method $Method -Ctx $Ctx
        $srcs = @(foreach ($ao in $aos) { Get-TcpkIdunnoRequestSource -Origin $ao -Ctx $Ctx })
        # Every origin must be request input: a value reassigned from something else is not.
        if ($aos.Count -gt 0 -and @($srcs | Where-Object { -not $_ }).Count -eq 0) { $site.Source = $srcs[0] }
    }

    # Every call before the sink in this method must be a plain read (see TcpkIdunnoBenign).
    $gates = New-Object 'System.Collections.Generic.List[string]'
    foreach ($g in $Method.Body.Instructions) {
        if ($g.Offset -ge $Ins.Offset) { break }
        $lab = Get-TcpkIdunnoBlocker -Ins $g -Method $Method -Ctx $Ctx
        if ($lab -and -not $gates.Contains($lab)) { $gates.Add($lab) }
    }
    $site.Gates = $gates.ToArray()
    $site.Proven = ($site.Reached -and $site.ReceiverOk -and [bool]$site.Source -and $gates.Count -eq 0)
    return $site
}

# Read the DLL's IL (in memory, disposed, so no file handle outlives the call). Read=$false
# when Cecil is unavailable or the image is not a readable managed assembly, so the caller
# can tell "no sink" from "not looked at". An assembly that is not Idunno.AntiCsrf by name
# or type returns before its IL is walked, unless -Force (the published hash matched).
function Get-TcpkIdunnoAntiCsrfIl {
    param([Parameter(Mandatory)][string]$DllPath, [switch]$Force)
    $r = [pscustomobject]@{ Read = $false; AssemblyName = ''; IsIdunno = $false; HasModuleType = $false; CtorSites = @(); Sites = @(); Proven = $null }
    if (-not (Initialize-TcpkCecil)) { return $r }
    $asm = $null
    try {
        $rp = New-Object Mono.Cecil.ReaderParameters
        $rp.InMemory = $true
        $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($DllPath, $rp)
    } catch { return $r }
    try {
        $mod = $asm.MainModule
        $r.AssemblyName = "$($asm.Name.Name)"
        $r.IsIdunno = ($r.AssemblyName -ieq 'Idunno.AntiCsrf') -or ($null -ne $mod.GetType('Idunno.AntiCsrf.AntiCsrfModule'))
        $r.Read = $true
        if (-not $r.IsIdunno -and -not $Force) { return $r }

        $ctx = @{ Module = $mod; Starts = @{}; FieldStores = $null; LocalStores = @{}; Benign = @{} }
        $entry = Get-TcpkIdunnoEntry -Module $mod
        $r.HasModuleType = $entry.HasModuleType
        $ctors = New-Object 'System.Collections.Generic.List[string]'
        $sites = New-Object 'System.Collections.Generic.List[object]'
        foreach ($t in @($mod.GetTypes())) {
            foreach ($m in @($t.Methods)) {
                if (-not $m.HasBody) { continue }
                $instrs = @($m.Body.Instructions)
                $ctorHere = $false
                foreach ($ins in $instrs) {
                    if (Test-TcpkIdunnoUnkeyedNew $ins) { $ctorHere = $true; $ctors.Add("$(Format-TcpkIdunnoMethod $m) $(Format-TcpkIdunnoIns $ins)") }
                }
                $path = $null
                foreach ($ins in $instrs) {
                    $code = "$($ins.OpCode.Code)"
                    if (@('Call', 'Callvirt', 'Ldftn', 'Ldvirtftn') -notcontains $code) { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if (-not $mref -or "$($mref.Name)" -ne 'Deserialize') { continue }
                    $kind = $script:TcpkIdunnoStateFormatters["$($mref.DeclaringType.FullName)"]
                    if (-not $kind) { continue }
                    if ($null -eq $path) { $path = Get-TcpkIdunnoPath -Method $m -Entry $entry -Ctx $ctx }
                    $s = Get-TcpkIdunnoSinkSite -Method $m -Ins $ins -MRef $mref -Kind $kind -Ctx $ctx -CtorInMethod $ctorHere -Path $path
                    if ($s) { $sites.Add($s) }
                }
            }
        }
        $r.CtorSites = $ctors.ToArray()
        $r.Sites = $sites.ToArray()
        $r.Proven = @($r.Sites | Where-Object { $_.Proven }) | Select-Object -First 1
    } catch {
        # A body Cecil cannot walk: report it as not read rather than as clean.
        $r.Read = $false
        $r.Sites = @()
    } finally {
        if ($asm) { $asm.Dispose() }
    }
    return $r
}

# ---------------------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------------------

# Path key for comparisons: full path, '/' separators, no trailing separator, lower case.
function ConvertTo-TcpkIdunnoPathKey {
    param([string]$Path)
    $p = $Path
    try { $p = [IO.Path]::GetFullPath($Path) } catch { }
    return $p.Replace('\', '/').TrimEnd('/').ToLowerInvariant()
}

function Test-TcpkIdunnoPathUnder {
    param([string]$Child, [string]$Parent)
    return $Child.StartsWith($Parent + '/')
}

function Read-TcpkIdunnoXml {
    param([string]$Path)
    $raw = $null
    try { $raw = [IO.File]::ReadAllText($Path) } catch {
        return [pscustomobject]@{ Doc = $null; Error = "read failed: $($_.Exception.Message)" }
    }
    $doc = New-Object System.Xml.XmlDocument
    $doc.XmlResolver = $null
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore
    $settings.XmlResolver = $null
    $sr = $null; $xr = $null
    try {
        $sr = New-Object System.IO.StringReader($raw)
        $xr = [System.Xml.XmlReader]::Create($sr, $settings)
        $doc.Load($xr)
    } catch {
        return [pscustomobject]@{ Doc = $null; Error = "XML parse failed: $($_.Exception.Message)" }
    } finally {
        if ($xr) { $xr.Dispose() }
        if ($sr) { $sr.Dispose() }
    }
    return [pscustomobject]@{ Doc = $doc; Error = '' }
}

# The element a section really lives in: itself, or the root of its configSource file.
# configSource must be a relative path at or below the config's folder. Never throws: a bad
# value becomes an Error the caller reports.
function Resolve-TcpkIdunnoConfigSource {
    param([string]$ConfigPath, $Element)
    $cs = "$($Element.GetAttribute('configSource'))"
    if (-not $cs) { return [pscustomobject]@{ Element = $Element; Source = $ConfigPath; Error = '' } }
    $sep = [IO.Path]::DirectorySeparatorChar
    $rel = $cs -replace '[\\/]', $sep
    # .NET Framework path APIs throw on these characters; check before calling any of them.
    if ($rel.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) {
        return [pscustomobject]@{ Element = $null; Source = $cs; Error = "configSource '$cs' has a character that is not valid in a path" }
    }
    $full = $null
    try {
        if ([IO.Path]::IsPathRooted($rel) -or (($rel -split [regex]::Escape($sep)) -contains '..')) {
            return [pscustomobject]@{ Element = $null; Source = $cs; Error = "configSource '$cs' is not a relative path below the config folder" }
        }
        $full = [IO.Path]::Combine([IO.Path]::GetDirectoryName($ConfigPath), $rel)
    } catch {
        return [pscustomobject]@{ Element = $null; Source = $cs; Error = "configSource '$cs' is not a usable path" }
    }
    $x = Read-TcpkIdunnoXml -Path $full
    if ($x.Error) {
        try { Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath $full } catch { }
        return [pscustomobject]@{ Element = $null; Source = $full; Error = "configSource $full $($x.Error)" }
    }
    $root = $x.Doc.DocumentElement
    if (-not $root -or $root.LocalName -ne $Element.LocalName) {
        return [pscustomobject]@{ Element = $null; Source = $full; Error = "configSource $full has no <$($Element.LocalName)> root" }
    }
    return [pscustomobject]@{ Element = $root; Source = $full; Error = '' }
}

# One config file as a model: its module collections (with <location> scope and the ordered
# add / remove / clear operations), its <csrfSettings>, the Integrated-mode validation flag
# and, for applicationHost.config, the site / application -> physical folder map. Parsed
# once per run through $Cache. A read or parse failure is recorded as a scan skip and kept
# on the model, never dropped.
function Get-TcpkIdunnoConfig {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Cache)
    $key = ConvertTo-TcpkIdunnoPathKey $Path
    if ($Cache.ContainsKey($key)) { return $Cache[$key] }
    $m = [pscustomobject]@{
        File = $Path; Key = $key; Ok = $false; Error = ''; IsAppHost = ((Split-Path -Leaf $Path) -ieq 'applicationHost.config')
        Collections = @(); Csrf = $null; NoIntegratedValidation = $false; Validations = @(); Sites = @{}; Vdirs = @{}
    }
    $Cache[$key] = $m
    $x = Read-TcpkIdunnoXml -Path $Path
    if ($x.Error) {
        $m.Error = $x.Error
        try { Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath $Path } catch { }
        return $m
    }
    $m.Ok = $true
    $doc = $x.Doc

    $colls = New-Object 'System.Collections.Generic.List[object]'
    foreach ($el in @($doc.SelectNodes("//*[local-name()='httpModules' or local-name()='modules']"))) {
        $parent = "$($el.ParentNode.LocalName)"
        $section = $null
        if ($parent -eq 'system.web' -and $el.LocalName -eq 'httpModules') { $section = 'system.web/httpModules' }
        elseif ($parent -eq 'system.webServer' -and $el.LocalName -eq 'modules') { $section = 'system.webServer/modules' }
        if (-not $section) { continue }
        $loc = $null; $inherit = $true
        $locEl = $el.ParentNode.ParentNode
        if ($locEl -and $locEl.LocalName -eq 'location') {
            $loc = "$($locEl.GetAttribute('path'))"
            if ("$($locEl.GetAttribute('inheritInChildApplications'))" -ieq 'false') { $inherit = $false }
        }
        $res = Resolve-TcpkIdunnoConfigSource -ConfigPath $Path -Element $el
        $ops = New-Object 'System.Collections.Generic.List[object]'
        if ($res.Element) {
            foreach ($n in @($res.Element.ChildNodes)) {
                if ($n.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                $ln = $n.LocalName
                if ($ln -ne 'add' -and $ln -ne 'remove' -and $ln -ne 'clear') { continue }
                $type = "$($n.GetAttribute('type'))"
                $ops.Add([pscustomobject]@{
                    Op = $ln; Name = "$($n.GetAttribute('name'))"; Type = $type.Trim()
                    IsIdunno = ($ln -eq 'add' -and $type -match '^\s*Idunno\.AntiCsrf\.AntiCsrfModule\s*(,|$)')
                })
            }
        }
        $colls.Add([pscustomobject]@{ Section = $section; Location = $loc; Inherit = $inherit; Ops = $ops.ToArray(); Source = $res.Source; Error = $res.Error })
    }
    $m.Collections = $colls.ToArray()

    $csEl = $doc.SelectSingleNode("//*[local-name()='csrfSettings']")
    if ($csEl) {
        $res = Resolve-TcpkIdunnoConfigSource -ConfigPath $Path -Element $csEl
        if ($res.Element) {
            $m.Csrf = [pscustomobject]@{ State = 'Present'; File = $res.Source; Cookie = "$($res.Element.GetAttribute('cookieName'))"; Field = "$($res.Element.GetAttribute('formFieldName'))"; Error = '' }
        } else {
            $m.Csrf = [pscustomobject]@{ State = 'Unknown'; File = $Path; Cookie = ''; Field = ''; Error = $res.Error }
        }
    }

    # <validation validateIntegratedModeConfiguration>, with its <location> scope, so the chain
    # can work out which level's value applies to an application.
    $vals = New-Object 'System.Collections.Generic.List[object]'
    foreach ($v in @($doc.SelectNodes("//*[local-name()='system.webServer']/*[local-name()='validation']"))) {
        $vloc = $null; $vinh = $true
        $vl = $v.ParentNode.ParentNode
        if ($vl -and $vl.LocalName -eq 'location') {
            $vloc = "$($vl.GetAttribute('path'))"
            if ("$($vl.GetAttribute('inheritInChildApplications'))" -ieq 'false') { $vinh = $false }
        }
        $res = Resolve-TcpkIdunnoConfigSource -ConfigPath $Path -Element $v
        if ($res.Error) {
            $vals.Add([pscustomobject]@{ Value = ''; Unknown = $true; Error = $res.Error; Location = $vloc; Inherit = $vinh })
            continue
        }
        $a = "$($res.Element.GetAttribute('validateIntegratedModeConfiguration'))"
        if (-not $a) { continue }
        $vals.Add([pscustomobject]@{ Value = $a; Unknown = $false; Error = ''; Location = $vloc; Inherit = $vinh })
        if ($null -eq $vloc -and $a -ieq 'false') { $m.NoIntegratedValidation = $true }
    }
    $m.Validations = $vals.ToArray()

    if ($m.IsAppHost) {
        foreach ($site in @($doc.SelectNodes("//*[local-name()='sites']/*[local-name()='site']"))) {
            $sn = "$($site.GetAttribute('name'))"
            foreach ($app in @($site.SelectNodes("*[local-name()='application']"))) {
                $ap = "$($app.GetAttribute('path'))".TrimEnd('/')
                $vd = $app.SelectSingleNode("*[local-name()='virtualDirectory'][@path='/']")
                if (-not $vd) { continue }
                $phys = [Environment]::ExpandEnvironmentVariables("$($vd.GetAttribute('physicalPath'))")
                if ($phys) { $m.Sites[("$sn$ap").ToLowerInvariant()] = $phys }
                # Other virtual directories of the application: content of that application, not one of their own.
                foreach ($ov in @($app.SelectNodes("*[local-name()='virtualDirectory']"))) {
                    $vp = "$($ov.GetAttribute('path'))".TrimEnd('/')
                    if (-not $vp) { continue }
                    $vphys = [Environment]::ExpandEnvironmentVariables("$($ov.GetAttribute('physicalPath'))")
                    if ($vphys) { $m.Vdirs[("$sn$ap$vp").ToLowerInvariant()] = $vphys }
                }
            }
        }
    }
    return $m
}

# The nearest folder with its own bin\ at $TargetDir or between it and the application root
# ($null when there is none): that folder is a nested application, and config aimed at it is
# not this application's.
function Get-TcpkIdunnoNestedAppDir {
    param([string]$TargetDir, [string]$RootKey)
    $walk = $TargetDir
    for ($i = 0; $i -lt 64 -and $walk; $i++) {
        if ((ConvertTo-TcpkIdunnoPathKey $walk) -eq $RootKey) { return $null }
        $hasBin = $false
        try { $hasBin = [IO.Directory]::Exists([IO.Path]::Combine($walk, 'bin')) } catch { }
        if ($hasBin) { return $walk }
        $up = $null
        try { $up = [IO.Path]::GetDirectoryName($walk) } catch { }
        if (-not $up -or $up -eq $walk) { break }
        $walk = $up
    }
    return $null
}

function Test-TcpkIdunnoNestedApp {
    param([string]$TargetDir, [string]$RootKey)
    return [bool](Get-TcpkIdunnoNestedAppDir -TargetDir $TargetDir -RootKey $RootKey)
}

# Merge order inside one config file: root-level and <location path="" / "."> first, then
# deeper <location> paths (IIS merges by config path depth, not document order).
function Get-TcpkIdunnoLocDepth {
    param($Location)
    if ($null -eq $Location -or $Location -eq '' -or $Location -eq '.') { return 0 }
    return (1 + @($Location.Trim('/', '\') -split '[\\/]').Count)
}

function New-TcpkIdunnoScope {
    param([string]$Kind, [string]$Scope = '', [int]$Dist = 0)
    [pscustomobject]@{ Kind = $Kind; Scope = $Scope; Dist = $Dist }
}

function Get-TcpkIdunnoSegs {
    param([string]$Key)
    return @($Key.Trim('/').Split('/') | Where-Object { $_ }).Count
}

# How an applicationHost.config collection (or <validation>) applies to the application whose
# <sites> keys are $AppUrls ('site' or 'site/app', lower case): 'full', 'scoped' (a path
# inside it) or 'none', with Dist = configuration levels between where it applies and the
# application (server-wide applies first). A <location> on an ancestor site / application
# path applies unless inheritInChildApplications="false"; one on a nested application does
# not apply here.
function Get-TcpkIdunnoAppHostScope {
    param($Config, $Item, [string[]]$AppUrls)
    $loc = $Item.Location
    if ($null -eq $loc -or $loc -eq '' -or $loc -eq '.') { return (New-TcpkIdunnoScope 'full' '' 1000000) }
    $l = $loc.Trim('/').ToLowerInvariant()
    foreach ($u in $AppUrls) { if ($u -eq $l) { return (New-TcpkIdunnoScope 'full' '' 0) } }
    $best = -1
    foreach ($u in $AppUrls) {
        if ($u.StartsWith("$l/")) {
            $dd = (Get-TcpkIdunnoSegs $u) - (Get-TcpkIdunnoSegs $l)
            if ($best -lt 0 -or $dd -lt $best) { $best = $dd }
        }
    }
    if ($best -ge 0) {
        if ($Item.Inherit) { return (New-TcpkIdunnoScope 'full' '' $best) }
        return (New-TcpkIdunnoScope 'none')
    }
    foreach ($u in $AppUrls) {
        if (-not $l.StartsWith("$u/")) { continue }
        foreach ($k in @($Config.Sites.Keys)) {
            if ($k.Length -gt $u.Length -and $k.StartsWith("$u/") -and ($l -eq $k -or $l.StartsWith("$k/"))) { return (New-TcpkIdunnoScope 'none') }
        }
        return (New-TcpkIdunnoScope 'scoped' $l.Substring($u.Length + 1))
    }
    return (New-TcpkIdunnoScope 'none')
}

# The same for a web.config collection (or <validation>). $IsApp: the config is the
# application's own web.config, else an in-scan parent folder's.
function Get-TcpkIdunnoWebConfigScope {
    param($Config, $Item, [string]$RootKey, [bool]$IsApp)
    $cfgDir = [IO.Path]::GetDirectoryName($Config.File)
    $own = [Math]::Max(0, (Get-TcpkIdunnoSegs $RootKey) - (Get-TcpkIdunnoSegs (ConvertTo-TcpkIdunnoPathKey $cfgDir)))
    $loc = $Item.Location
    if ($null -eq $loc) { return (New-TcpkIdunnoScope 'full' '' $own) }
    if ($loc -eq '' -or $loc -eq '.') {
        if ($IsApp -or $Item.Inherit) { return (New-TcpkIdunnoScope 'full' '' $own) }
        return (New-TcpkIdunnoScope 'none')
    }
    $targetPath = $null
    try { $targetPath = [IO.Path]::Combine($cfgDir, ($loc -replace '[\\/]', [IO.Path]::DirectorySeparatorChar)) } catch { return (New-TcpkIdunnoScope 'none') }
    $t = ConvertTo-TcpkIdunnoPathKey $targetPath
    if ($t -eq $RootKey) { return (New-TcpkIdunnoScope 'full' '' 0) }
    if (Test-TcpkIdunnoPathUnder -Child $RootKey -Parent $t) {
        if ($Item.Inherit) { return (New-TcpkIdunnoScope 'full' '' ((Get-TcpkIdunnoSegs $RootKey) - (Get-TcpkIdunnoSegs $t))) }
        return (New-TcpkIdunnoScope 'none')
    }
    if (Test-TcpkIdunnoPathUnder -Child $t -Parent $RootKey) {
        if (Test-TcpkIdunnoNestedApp -TargetDir $targetPath -RootKey $RootKey) { return (New-TcpkIdunnoScope 'none') }
        return (New-TcpkIdunnoScope 'scoped' $t.Substring($RootKey.Length + 1))
    }
    return (New-TcpkIdunnoScope 'none')
}

# Apply one collection's operations to the live registration set of its section.
function Add-TcpkIdunnoOps {
    param($Coll, $Config, [string]$Via, [string]$Scope, [hashtable]$Live, $Removed, $Used)
    $sec = $Coll.Section
    if (-not $Live.ContainsKey($sec)) { $Live[$sec] = [ordered]@{} }
    $set = $Live[$sec]
    foreach ($op in $Coll.Ops) {
        switch ($op.Op) {
            'add' {
                if ($op.IsIdunno) {
                    $set[$op.Name] = [pscustomobject]@{ Section = $sec; Name = $op.Name; File = $Config.File; Source = $Coll.Source; Via = $Via; Scope = $Scope; Location = $Coll.Location }
                    [void]$Used.Add($Config.Key)
                }
            }
            'remove' {
                if ($set.Contains($op.Name)) {
                    $Removed.Add("$($set[$op.Name].File) registration '$($op.Name)' removed by $($Config.File)")
                    $set.Remove($op.Name)
                }
            }
            'clear' {
                foreach ($k in @($set.Keys)) { $Removed.Add("$($set[$k].File) registration '$k' cleared by $($Config.File)") }
                $set.Clear()
            }
        }
    }
}

# The module registrations that apply to the application rooted at $AppRoot (the folder
# above bin\). Sources: applicationHost.config (server-wide, and <location> paths of this
# application or an ancestor site path), the in-scan parent web.configs (root-level,
# <location path=""> unless inheritInChildApplications="false", or a <location> aimed at this
# folder or an ancestor of it) and the application's own web.config. Everything that applies
# is merged in one order, as IIS merges configuration: by configuration level (furthest from
# the application first), then applicationHost.config before parent before own, then document
# order. Entries that only cover a sub-path (a <location path="sub">, a sub-folder web.config)
# come back as Scoped. $ByDir maps folder key -> web.config path for the scan; $AppHosts are
# parsed applicationHost.config models.
function Get-TcpkIdunnoAppRegistrations {
    param([string]$AppRoot, [string]$ScanRootKey, [hashtable]$ByDir, [object[]]$AppHosts = @(), [hashtable]$Cache, $Used)
    $rootKey = ConvertTo-TcpkIdunnoPathKey $AppRoot
    $live = @{}
    $removed = New-Object 'System.Collections.Generic.List[string]'
    $scoped = New-Object 'System.Collections.Generic.List[object]'
    $read = New-Object 'System.Collections.Generic.List[string]'
    $unread = New-Object 'System.Collections.Generic.List[string]'
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $items = New-Object 'System.Collections.Generic.List[object]'
    $noVal = $false
    $valUnknown = $false
    $notAnApp = ''
    $rank = 0

    $track = {
        param($c)
        if ($c.Ok) { $read.Add($c.File) } else { $unread.Add("$($c.File) ($($c.Error))") }
        foreach ($col in $c.Collections) { if ($col.Error) { $unread.Add($col.Error) } }
    }
    # Queue one config's collections and <validation> values with their scope for this app.
    $collect = {
        param($c, $classify, [string]$label)
        $i = 0
        foreach ($col in $c.Collections) {
            $sc = & $classify $col
            if ($sc.Kind -ne 'none') { $items.Add([pscustomobject]@{ Dist = $sc.Dist; Rank = $rank; I = $i; Cfg = $c; Coll = $col; Val = $null; Kind = $sc.Kind; Scope = $sc.Scope; Label = $label }) }
            $i++
        }
        foreach ($v in $c.Validations) {
            $sc = & $classify $v
            if ($sc.Kind -eq 'full') { $items.Add([pscustomobject]@{ Dist = $sc.Dist; Rank = $rank; I = $i; Cfg = $c; Coll = $null; Val = $v; Kind = 'full'; Scope = ''; Label = $label }) }
            $i++
        }
    }

    $isApp = $false
    foreach ($ah in $AppHosts) {
        & $track $ah
        $appUrls = @(foreach ($k in @($ah.Sites.Keys)) { if ((ConvertTo-TcpkIdunnoPathKey $ah.Sites[$k]) -eq $rootKey) { $k } })
        if ($appUrls.Count) { $isApp = $true }
        elseif ($ah.Sites.Count) {
            # Locations that register the module but cannot be related to this folder.
            foreach ($col in $ah.Collections) {
                if ([string]::IsNullOrEmpty($col.Location) -or $col.Location -eq '.') { continue }
                if (@($col.Ops | Where-Object { $_.IsIdunno }).Count -eq 0) { continue }
                $notes.Add("$($ah.File) <location path=`"$($col.Location)`"> not related to $AppRoot (no <application> in its <sites> maps to this folder)")
            }
        }
        & $collect $ah { param($x) Get-TcpkIdunnoAppHostScope -Config $ah -Item $x -AppUrls $appUrls } 'apphost'
        $rank++
    }

    # An applicationHost.config that lists applications but none for this folder, while the
    # folder sits inside one of its applications or virtual directories: ASP.NET probes only
    # an application's own bin\, so this bin\ is not one.
    if (-not $isApp) {
        foreach ($ah in $AppHosts) {
            if ($notAnApp) { break }
            foreach ($k in @($ah.Sites.Keys)) {
                $pk = ConvertTo-TcpkIdunnoPathKey $ah.Sites[$k]
                if (Test-TcpkIdunnoPathUnder -Child $rootKey -Parent $pk) { $notAnApp = "$($ah.File) lists no <application> for $AppRoot; the folder is inside application '$k' ($($ah.Sites[$k]))"; break }
            }
            if ($notAnApp) { break }
            foreach ($k in @($ah.Vdirs.Keys)) {
                $pk = ConvertTo-TcpkIdunnoPathKey $ah.Vdirs[$k]
                if ($pk -eq $rootKey -or (Test-TcpkIdunnoPathUnder -Child $rootKey -Parent $pk)) { $notAnApp = "$($ah.File) maps $AppRoot as virtual directory '$k' of an application, not as an application"; break }
            }
        }
    }

    # Parent folders inside the scan, top-down.
    $chainDirs = New-Object 'System.Collections.Generic.List[string]'
    $d = $rootKey
    while ($true) {
        $parentDir = $d.Substring(0, [Math]::Max(0, $d.LastIndexOf('/')))
        if (-not $parentDir -or $parentDir -eq $d) { break }
        if (-not $ScanRootKey -or -not ($parentDir -eq $ScanRootKey -or (Test-TcpkIdunnoPathUnder -Child $parentDir -Parent $ScanRootKey))) { break }
        $chainDirs.Insert(0, $parentDir)
        $d = $parentDir
    }
    foreach ($dirKey in $chainDirs) {
        if (-not $ByDir.ContainsKey($dirKey)) { continue }
        $c = Get-TcpkIdunnoConfig -Path $ByDir[$dirKey] -Cache $Cache
        & $track $c
        & $collect $c { param($x) Get-TcpkIdunnoWebConfigScope -Config $c -Item $x -RootKey $rootKey -IsApp $false } 'parent'
        $rank++
    }

    $app = $null
    $own = Join-Path $AppRoot 'web.config'
    if (Test-Path -LiteralPath $own -PathType Leaf) {
        $app = Get-TcpkIdunnoConfig -Path $own -Cache $Cache
        & $track $app
        & $collect $app { param($x) Get-TcpkIdunnoWebConfigScope -Config $app -Item $x -RootKey $rootKey -IsApp $true } 'app'
        $rank++
    }

    # One merge in configuration order. The key is unique, so PS 5.1's Sort-Object is enough.
    foreach ($it in @($items | Sort-Object @{ Expression = 'Dist'; Descending = $true }, @{ Expression = 'Rank'; Descending = $false }, @{ Expression = 'I'; Descending = $false })) {
        $c = $it.Cfg
        if ($it.Val) {
            $valUnknown = [bool]$it.Val.Unknown
            $noVal = (-not $valUnknown) -and ($it.Val.Value -ieq 'false')
            if ($it.Val.Error) { $unread.Add($it.Val.Error) }
            continue
        }
        $col = $it.Coll
        $loc = if ($null -eq $col.Location -or $col.Location -eq '') { '' } else { " <location path=`"$($col.Location)`">" }
        $via = switch ($it.Label) {
            'apphost' { if ($loc) { "$($c.File)$loc" } else { "$($c.File) (server-wide)" } }
            'parent'  { "inherited from $($c.File)$loc" }
            default   { if ($it.Kind -eq 'scoped') { "$($c.File)$loc" } else { 'app' } }
        }
        if ($it.Kind -eq 'full') {
            Add-TcpkIdunnoOps -Coll $col -Config $c -Via $via -Scope '' -Live $live -Removed $removed -Used $Used
        } else {
            $tmp = @{}
            Add-TcpkIdunnoOps -Coll $col -Config $c -Via $via -Scope $it.Scope -Live $tmp -Removed $removed -Used $Used
            foreach ($sv in $tmp.Values) { foreach ($e in $sv.Values) { $scoped.Add($e) } }
        }
    }

    # Sub-folder web.configs of this application (not of a nested application with its own bin\).
    foreach ($dirKey in @($ByDir.Keys)) {
        if (-not (Test-TcpkIdunnoPathUnder -Child $dirKey -Parent $rootKey)) { continue }
        $cfgPath = $ByDir[$dirKey]
        if (Test-TcpkIdunnoNestedApp -TargetDir (Split-Path -Parent $cfgPath) -RootKey $rootKey) { continue }
        $cfg = Get-TcpkIdunnoConfig -Path $cfgPath -Cache $Cache
        $rel = $dirKey.Substring($rootKey.Length + 1)
        foreach ($col in $cfg.Collections) {
            if ($null -ne $col.Location -and $col.Location -ne '' -and $col.Location -ne '.') { continue }
            $tmp = @{}
            Add-TcpkIdunnoOps -Coll $col -Config $cfg -Via "sub-folder $($cfg.File)" -Scope $rel -Live $tmp -Removed $removed -Used $Used
            foreach ($sv in $tmp.Values) { foreach ($e in $sv.Values) { $scoped.Add($e) } }
        }
    }

    $effective = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sv in $live.Values) { foreach ($e in $sv.Values) { $effective.Add($e) } }

    # <csrfSettings>: the application's web.config first, then the nearest in-scan parent.
    $csrf = $null
    if ($app -and $app.Csrf) { $csrf = $app.Csrf }
    else {
        for ($i = $chainDirs.Count - 1; $i -ge 0; $i--) {
            if (-not $ByDir.ContainsKey($chainDirs[$i])) { continue }
            $c = Get-TcpkIdunnoConfig -Path $ByDir[$chainDirs[$i]] -Cache $Cache
            if ($c.Csrf) { $csrf = $c.Csrf; break }
        }
    }

    return [pscustomobject]@{
        Effective = $effective.ToArray(); Scoped = $scoped.ToArray(); Removed = $removed.ToArray()
        Read = @($read | Select-Object -Unique); Unread = @($unread | Select-Object -Unique); Notes = $notes.ToArray()
        App = $app; Csrf = $csrf; NoIntegratedValidation = $noVal; IntegratedValidationUnknown = $valUnknown; NotAnApp = $notAnApp
    }
}

# The cookie and form field names the module reads, labelled by where each came from.
function Format-TcpkIdunnoAntiCsrfTrigger {
    param($Csrf, $App, [string]$AppRoot)
    if ($Csrf -and $Csrf.State -eq 'Present') {
        $c = if ($Csrf.Cookie) { "$($Csrf.Cookie)" } else { '__CSRFCOOKIE (attribute absent, default per MNDT-2026-0048)' }
        $f = if ($Csrf.Field)  { "$($Csrf.Field)" }  else { '__CSRFTOKEN (attribute absent, default per MNDT-2026-0048)' }
        return "cookie $c, form field $f (from <csrfSettings> in $($Csrf.File))"
    }
    if ($Csrf -and $Csrf.State -eq 'Unknown') { return "cookie and form field names not read ($($Csrf.Error))" }
    if ($App -and $App.Ok) {
        return ("cookie __CSRFCOOKIE, form field RaiseException (no <csrfSettings> in $($App.File) or its in-scan parents; " +
            'MNDT-2026-0048 says that without the section a setter bug sets the field name to RaiseException)')
    }
    return "cookie and form field names not read (no readable web.config at $AppRoot)"
}

function Format-TcpkIdunnoReg {
    param($Reg)
    $where = if ($Reg.Via -eq 'app') { "$($Reg.File)" } else { "$($Reg.Via)" }
    # Other Via values already name the <location> or the sub-folder; the config-only pass uses Via 'app'.
    if ($Reg.Via -eq 'app' -and $Reg.Location) { $where += " <location path=`"$($Reg.Location)`">" }
    if ($Reg.Source -and $Reg.Source -ne $Reg.File) { $where += " (configSource $($Reg.Source))" }
    return "$where $($Reg.Section) name=`"$($Reg.Name)`""
}

# What the registered sections mean for the IIS pipeline. TCPK does not read the app pool.
function Format-TcpkIdunnoPipeline {
    param([object[]]$Regs)
    $secs = @($Regs | ForEach-Object { $_.Section } | Select-Object -Unique)
    $hasWeb = $secs -contains 'system.web/httpModules'
    $hasSrv = $secs -contains 'system.webServer/modules'
    if ($hasWeb -and $hasSrv) { return 'It is registered for both the Classic pipeline (system.web/httpModules) and the Integrated pipeline (system.webServer/modules).' }
    if ($hasSrv) { return 'It is registered in system.webServer/modules, which IIS runs on the Integrated pipeline.' }
    return ('It is registered only in system.web/httpModules, which IIS 7+ runs on the Classic pipeline. On the Integrated pipeline ' +
        'IIS rejects the entry with HTTP 500.22, or skips it when validateIntegratedModeConfiguration is false.')
}

# ---------------------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------------------

# Emit the findings. $Candidates are the PE files Test-TcpkDeserialization pre-filtered with
# Test-TcpkIdunnoAntiCsrfCandidate; $ConfigPaths are the web.config / applicationHost.config
# files its PE walk saw. Returns @{ Findings; Claimed }: Claimed holds the DLL paths this
# pass reported as the vulnerable (or unverified) library, so the caller can drop the
# generic deser.objectstateformatter token finding for the same file.
function Get-TcpkIdunnoAntiCsrfFindings {
    param([Parameter(Mandatory)][string]$Path, [object[]]$Candidates = @(), [string[]]$ConfigPaths = @(), [switch]$WalkCut)

    $cve  = $script:TcpkIdunnoAntiCsrfCve
    $cvss = $script:TcpkIdunnoAntiCsrfCvss
    $flow = $script:TcpkIdunnoAntiCsrfFlow
    $fix  = "$($script:TcpkIdunnoAntiCsrfFixRemove) $($script:TcpkIdunnoAntiCsrfFixAssess)"
    $out = New-Object 'System.Collections.Generic.List[object]'
    $claimed = New-Object 'System.Collections.Generic.HashSet[string]'
    $used = New-Object 'System.Collections.Generic.HashSet[string]'
    $cache = @{}

    # The scan root as an absolute path. Convert-Path resolves a relative -Path against the
    # PowerShell location; [IO.Path]::GetFullPath would use the process directory instead.
    $scanRootKey = ''
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $abs = $Path
        try { $abs = Convert-Path -LiteralPath $Path -ErrorAction Stop } catch { }
        $scanRootKey = ConvertTo-TcpkIdunnoPathKey $abs
    }

    # IIS configuration history keeps old applicationHost.config copies in CFGHISTORY_<n>
    # folders (configHistory). They are not the running configuration.
    $ConfigPaths = @($ConfigPaths | Where-Object { $_ -and ((Split-Path -Leaf (Split-Path -Parent $_)) -notmatch '^CFGHISTORY_\d+$') })
    $byDir = @{}
    $appHostPaths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $ConfigPaths) {
        if ((Split-Path -Leaf $p) -ieq 'applicationHost.config') { $appHostPaths.Add($p) }
        else { $byDir[(ConvertTo-TcpkIdunnoPathKey (Split-Path -Parent $p))] = $p }
    }
    $appHosts = $null

    # Candidates whose analysis failed, by folder key: the config pass must not then claim that
    # folder holds no Idunno.AntiCsrf.dll. (No budget stop here: the IL walk is bounded per
    # sink, and stopping before the library would drop its finding.)
    $failed = @{}
    foreach ($c in $Candidates) {
        try {
            $dll = $c.FullName
            $sha = ''
            try { $sha = (Get-FileHash -LiteralPath $dll -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { }
            $build = if ($sha -and $script:TcpkIdunnoAntiCsrfBuilds.ContainsKey($sha)) { $script:TcpkIdunnoAntiCsrfBuilds[$sha] } else { '' }
            $il = Get-TcpkIdunnoAntiCsrfIl -DllPath $dll -Force:([bool]$build)

            # The pre-filter also passes an assembly that only REFERENCES Idunno.AntiCsrf (the
            # web app's own code, which implements ISuppressCsrfCheck). That is not the library.
            $isLib = [bool]$build -or $il.IsIdunno -or (-not $il.Read -and $c.Name -ieq 'Idunno.AntiCsrf.dll')
            if (-not $isLib) { continue }

            # hash    : the published SHA-256
            # il      : a Deserialize site proven from the IL
            # partial : Deserialize on a state formatter, not proven (see Evidence)
            # unread  : no hash match and the IL could not be read
            # clean   : IL read, no Deserialize on any state formatter
            $state = if ($build) { 'hash' } elseif (-not $il.Read) { 'unread' } elseif ($il.Proven) { 'il' } elseif (@($il.Sites).Count -gt 0) { 'partial' } else { 'clean' }

            $proof = New-Object 'System.Collections.Generic.List[string]'
            if ($build)   { $proof.Add("SHA-256 $sha is the published $build") }
            elseif ($sha) { $proof.Add("SHA-256 $sha is not one of the three published builds") }
            if (-not $il.Read) {
                $proof.Add('IL not read (Mono.Cecil unavailable or the image is not a readable managed assembly)')
            } elseif ($il.Proven) {
                $pv = $il.Proven
                $proof.Add("IL: $($pv.Kind)::Deserialize at $($pv.Where); $($pv.Receiver); argument from $($pv.Source)")
            } elseif (@($il.Sites).Count -gt 0) {
                foreach ($st in @($il.Sites | Select-Object -First 3)) {
                    $why = @()
                    if (-not $st.Reached) { $why += "not on the module's request path in the advisory's shape: $($st.PathWhy)" }
                    if (-not $st.ReceiverOk) { $why += $st.Receiver }
                    if (-not $st.Source) { $why += 'argument not traced to Request.Form or Request[...] on every path' }
                    if (@($st.Gates).Count) { $why += "called after $(@($st.Gates) -join ', '), which TCPK does not treat as a plain read" }
                    $proof.Add("IL: $($st.Kind)::Deserialize at $($st.Where), not proven: $($why -join '; ')")
                }
            } else {
                $ct = if (@($il.CtorSites).Count) { " (new ObjectStateFormatter() only at $(@($il.CtorSites | Select-Object -First 2) -join '; '))" } else { '' }
                $proof.Add("IL read: no Deserialize call or ldftn on ObjectStateFormatter, IStateFormatter, IFormatter or LosFormatter$ct")
            }

            $dllDir = Split-Path -Parent $dll
            $inBin = ((Split-Path -Leaf $dllDir) -ieq 'bin')
            $appRoot = if ($inBin) { Split-Path -Parent $dllDir } else { '' }
            $reg = $null
            if ($inBin) {
                if ($null -eq $appHosts) { $appHosts = @(foreach ($ap in $appHostPaths) { Get-TcpkIdunnoConfig -Path $ap -Cache $cache }) }
                $reg = Get-TcpkIdunnoAppRegistrations -AppRoot $appRoot -ScanRootKey $scanRootKey -ByDir $byDir -AppHosts $appHosts -Cache $cache -Used $used
            }

            $regs = @(); $ownRegs = @()
            if ($reg) {
                $regs = @($reg.Effective) + @($reg.Scoped)
                $ownRegs = @($reg.Effective | Where-Object { $_.Via -eq 'app' })
                if (@($reg.Removed).Count) { $proof.Add("removed: $(@($reg.Removed) -join '; ')") }
                if (@($reg.Unread).Count)  { $proof.Add("not read: $(@($reg.Unread) -join '; ')") }
                if (@($reg.Notes).Count)   { $proof.Add("not related: $(@($reg.Notes) -join '; ')") }
                if ($reg.NotAnApp)         { $proof.Add("not an application: $($reg.NotAnApp)") }
            }
            if ($regs.Count) {
                $proof.Add("registered: $(@($regs | ForEach-Object { Format-TcpkIdunnoReg $_ }) -join ' | ')")
                $proof.Add("trigger: $(Format-TcpkIdunnoAntiCsrfTrigger -Csrf $reg.Csrf -App $reg.App -AppRoot $appRoot)")
            }
            $ev = $proof -join ' | '

            if ($state -eq 'clean') {
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'deser.idunno-anticsrf-dll' `
                    -Severity 'INFO' -Confidence 'Likely-FP (IL)' `
                    -Title "Idunno.AntiCsrf build with no recognised ObjectStateFormatter Deserialize call ($cve)" `
                    -File $dll -Evidence $ev `
                    -Description ("$dll identifies as Idunno.AntiCsrf, its SHA-256 is not one of the published builds, and its IL has no " +
                        'Deserialize call or method-group reference on ObjectStateFormatter, IStateFormatter, IFormatter or LosFormatter. ' +
                        "TCPK does not recognise the advisory's sink in it. $($script:TcpkIdunnoAntiCsrfScope)") `
                    -Cwe @('CWE-502') -Fix $script:TcpkIdunnoAntiCsrfFixClean -AttributionBasis 'established-footprint'))
                continue
            }

            [void]$claimed.Add((ConvertTo-TcpkIdunnoPathKey $dll))
            $proven = ($state -eq 'hash' -or $state -eq 'il')
            $what = switch ($state) {
                'hash'    { "$dll is the published Idunno.AntiCsrf $build (SHA-256 match)." }
                'il'      { "$dll is an Idunno.AntiCsrf build that is not one of the published hashes. Its IL calls $($il.Proven.Kind)::Deserialize at $($il.Proven.Where), in a handler that IHttpModule.Init of Idunno.AntiCsrf.AntiCsrfModule subscribes (or a method such a handler calls directly), on a $($il.Proven.Receiver), with every value of the argument read from $($il.Proven.Source). Every call before it on that path is a request, cookie, string, attribute or settings read of the kind the advisory's flow makes. $($script:TcpkIdunnoAntiCsrfScope)" }
                'partial' { "$dll is an Idunno.AntiCsrf build that is not one of the published hashes. Its IL calls Deserialize on a state formatter, but TCPK could not prove the unkeyed sink on the module's request path (Evidence says what was not traced). $($script:TcpkIdunnoAntiCsrfScope)" }
                default   { "$dll is named Idunno.AntiCsrf, its SHA-256 is not one of the published builds and its IL could not be read. $($script:TcpkIdunnoAntiCsrfScope)" }
            }
            $nc = @('whether IIS serves this application', 'the app pool pipeline mode', 'which .aspx pages are reachable without authentication')
            if ($state -eq 'il') { $nc += 'whether this build checks the field some other way before the call' }
            $notChecked = "Not checked by TCPK: $(@($nc[0..($nc.Count - 2)]) -join ', '), and $($nc[-1])."
            $conf = if ($state -eq 'hash') { 'Confirmed' } elseif ($state -eq 'il') { 'Confirmed (IL)' } else { 'Inferred' }

            if (-not $inBin) {
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'deser.idunno-anticsrf-dll' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title $(if ($proven) { "Idunno.AntiCsrf with the unkeyed ObjectStateFormatter sink ships outside a bin folder ($cve)" } else { "Idunno.AntiCsrf.dll ships outside a bin folder, sink not proven ($cve)" }) `
                    -File $dll -Evidence $ev `
                    -Description ("$what ASP.NET loads an HTTP module from the application's bin\ folder or the GAC, and $dllDir is not a bin\ " +
                        "folder, so TCPK did not pair this copy with a web.config. Check where this copy gets deployed. $flow") `
                    -Cwe @('CWE-502') -Cvss $cvss -Fix $fix -AttributionBasis 'established-footprint'))
                continue
            }

            if ($regs.Count -eq 0) {
                $parts = @()
                if (@($reg.Read).Count)   { $parts += "Read: $(@($reg.Read) -join ', ')." }
                if (@($reg.Unread).Count) { $parts += "Not read: $(@($reg.Unread) -join '; '). A registration in a config TCPK could not read would load the module." }
                if (@($reg.Notes).Count)  { $parts += "TCPK could not relate $(@($reg.Notes).Count) applicationHost.config <location> registration(s) to this folder (Evidence lists them)." }
                if (-not $parts.Count)    { $parts += "No web.config was found for $appRoot." }
                $gap = if (@($reg.Unread).Count) { 'registration unknown, a config could not be read' } elseif (@($reg.Notes).Count) { 'no registration TCPK could relate to its application' } else { 'no registration found for its application' }
                $opener = if (@($reg.Notes).Count) { "TCPK related no registration of AntiCsrfModule to the application at $appRoot." } else { "No registration of AntiCsrfModule that TCPK read applies to the application at $appRoot." }
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'deser.idunno-anticsrf-dll' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title $(if ($proven) { "Idunno.AntiCsrf with the unkeyed ObjectStateFormatter sink ships, $gap ($cve)" } else { "Idunno.AntiCsrf.dll ships, sink not proven, $gap ($cve)" }) `
                    -File $dll -Evidence $ev `
                    -Description ("$what $opener " +
                        "$($parts -join ' ') It is also loaded if a config outside the scan (a parent web.config, applicationHost.config) registers it. $flow") `
                    -Cwe @('CWE-502') -Cvss $cvss -Fix $fix -AttributionBasis 'established-footprint'))
                continue
            }

            $pipe = Format-TcpkIdunnoPipeline -Regs $(if ($ownRegs.Count) { $ownRegs } else { $regs })
            $weak = ''; $tag = ''
            $httpOnly = (@($ownRegs | Where-Object { $_.Section -eq 'system.webServer/modules' }).Count -eq 0)
            if (-not $proven) {
                $weak = 'The sink in this copy is not proven (Evidence says why), so this is a lead until its hash or IL is checked.'
            } elseif ($reg.NotAnApp) {
                $tag = 'folder not an IIS application'
                $weak = ("$($reg.NotAnApp). ASP.NET loads an HTTP module from its application's own bin\ folder, not from a folder inside " +
                    'that application. Whether the running host maps this folder differently is not measured, so this is a lead.')
            } elseif (@($reg.Effective).Count -eq 0) {
                $tag = 'registered only below the application level'

                $weak = ('Every registration found applies only below the application level (a <location path> inside it or a sub-folder ' +
                    'web.config). HTTP modules are loaded per application, and TCPK did not check whether IIS accepts or applies an entry at ' +
                    'that level, so this is a lead.')
            } elseif ($ownRegs.Count -eq 0) {
                $tag = 'registration only from a parent config or applicationHost.config'
                $weak = ('The registration that applies comes from outside the application''s own web.config (an in-scan parent web.config or ' +
                    'applicationHost.config). Whether that config reaches this application on the running host (whether the folder is an IIS ' +
                    'application, and on which host) is not measured, so this is a lead.')
            } elseif ($httpOnly -and $reg.IntegratedValidationUnknown) {
                $tag = 'httpModules-only registration, Integrated validation setting not read'
                $weak = ('The application registers it only in system.web/httpModules, and the validateIntegratedModeConfiguration value that ' +
                    'applies to it could not be read (Evidence names the file). If it is false, the application runs on the Integrated pipeline, ' +
                    'where that entry is not loaded, so this is a lead.')
            } elseif ($httpOnly -and $reg.NoIntegratedValidation) {
                $tag = 'httpModules-only registration with Integrated validation off'
                $weak = ('The application registers it only in system.web/httpModules, and the configuration that applies to it sets ' +
                    'validateIntegratedModeConfiguration="false", which lets the application run on the Integrated pipeline, where that entry ' +
                    'is not loaded. Which pipeline the app pool uses is not measured, so this is a lead.')
            }

            if ($weak) {
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'deser.idunno-anticsrf-module' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title $(if ($proven) { "Idunno.AntiCsrf with the unkeyed ObjectStateFormatter sink, $tag ($cve)" } else { "Idunno.AntiCsrf module registered, sink not proven in this copy ($cve)" }) `
                    -File $dll -Evidence $ev `
                    -Description "$what $(if ($reg.NotAnApp) { if (@($reg.Effective).Count) { "A config TCPK read registers AntiCsrfModule for the folder $appRoot." } else { "A config TCPK read registers AntiCsrfModule only for paths below the folder $appRoot." } } elseif (@($reg.Effective).Count) { "A registration of AntiCsrfModule applies to the application at $appRoot." } else { "Registrations of AntiCsrfModule sit below the application at $appRoot." }) $pipe $weak $flow" `
                    -Cwe @('CWE-502') -Cvss $cvss -Fix $fix -AttributionBasis 'established-footprint'))
                continue
            }

            $files = @($ownRegs | ForEach-Object { "$($_.File)" } | Select-Object -Unique) -join ', '
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'deser.idunno-anticsrf-module' `
                -Severity 'CRITICAL' -Confidence $conf `
                -Title "Idunno.AntiCsrf module registered with the unkeyed ObjectStateFormatter sink ($cve)" `
                -File $dll -Evidence $ev `
                -Description "$what The application's own web.config ($files) registers Idunno.AntiCsrf.AntiCsrfModule. $pipe $flow $notChecked" `
                -Cwe @('CWE-502') -Cvss $cvss -Fix $fix -AttributionBasis 'established-footprint'))
        } catch {
            try { Write-TcpkLog -Level WARN -Component 'deser.idunno-anticsrf' -Message "skipped $($c.FullName): $($_.Exception.Message)" | Out-Null } catch { }
            try { Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath "$($c.FullName) (Idunno.AntiCsrf check failed: $($_.Exception.Message))" } catch { }
            try {
                $fk = ConvertTo-TcpkIdunnoPathKey (Split-Path -Parent $c.FullName)
                if (-not $failed.ContainsKey($fk)) { $failed[$fk] = New-Object 'System.Collections.Generic.List[string]' }
                $failed[$fk].Add("$($c.FullName)")
            } catch { }
        }
    }

    # Registrations no scanned DLL's application picked up: the assembly may load from the
    # GAC, or from a bin\ outside the scan. When the caller says its PE walk stopped at the
    # check budget (-WalkCut), a DLL may simply not have been reached, so absence is not claimed.
    $walkCut = [bool]$WalkCut
    $failedUnder = {
        param([string]$Key)
        @(foreach ($fk in @($failed.Keys)) { if (-not $Key -or $fk -eq $Key -or (Test-TcpkIdunnoPathUnder -Child $fk -Parent $Key)) { $failed[$fk] } })
    }
    foreach ($p in $ConfigPaths) {
        try {
            $k = ConvertTo-TcpkIdunnoPathKey $p
            if ($used.Contains($k)) { continue }
            # Cheap text check before parsing a config no application chain needed: without the
            # module name or a configSource it cannot register the module.
            if (-not $cache.ContainsKey($k)) {
                $raw = $null
                try { $raw = [IO.File]::ReadAllText($p) } catch { }
                if ($null -ne $raw -and $raw.IndexOf('AntiCsrfModule', [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
                    $raw.IndexOf('configSource', [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            }
            $cfg = Get-TcpkIdunnoConfig -Path $p -Cache $cache
            $adds = New-Object 'System.Collections.Generic.List[object]'
            foreach ($col in $cfg.Collections) {
                $tmp = @{}
                Add-TcpkIdunnoOps -Coll $col -Config $cfg -Via 'app' -Scope $(if ($col.Location) { $col.Location } else { '' }) -Live $tmp -Removed (New-Object 'System.Collections.Generic.List[string]') -Used (New-Object 'System.Collections.Generic.HashSet[string]')
                foreach ($sv in $tmp.Values) { foreach ($e in $sv.Values) { $adds.Add($e) } }
            }
            if ($adds.Count -eq 0) { continue }
            $regText = @($adds | ForEach-Object { Format-TcpkIdunnoReg $_ }) -join ' | '
            $cfgDir = Split-Path -Parent $cfg.File
            if ($cfg.IsAppHost) {
                # Where each registration's <location> lands, as far as this file's <sites> says.
                $unmapped = $false; $unsure = $false
                $maps = foreach ($e in $adds) {
                    if ([string]::IsNullOrEmpty($e.Location) -or $e.Location -eq '.') {
                        $fl = & $failedUnder ''
                        if ($fl.Count) { $unsure = $true; "server-wide; TCPK collected candidates it could not analyse ($($fl -join '; '); see the scan skips)" }
                        elseif ($walkCut) { $unsure = $true; 'server-wide; the scan stopped at its time budget before it read every file (see the scan skips)' }
                        else { 'server-wide' }
                        continue
                    }
                    $l = $e.Location.Trim('/').ToLowerInvariant(); $best = ''
                    foreach ($k in @($cfg.Sites.Keys)) { if (($l -eq $k -or $l.StartsWith("$k/")) -and $k.Length -gt $best.Length) { $best = $k } }
                    if (-not $best) { $unmapped = $true; "<location path=`"$($e.Location)`"> has no <site> entry"; continue }
                    $pk = ConvertTo-TcpkIdunnoPathKey $cfg.Sites[$best]
                    if ($scanRootKey -and ($pk -eq $scanRootKey -or (Test-TcpkIdunnoPathUnder -Child $pk -Parent $scanRootKey))) {
                        $fl = & $failedUnder $pk
                        if ($fl.Count) { $unsure = $true; "<location path=`"$($e.Location)`"> maps to $($cfg.Sites[$best]), where TCPK collected a candidate it could not analyse ($($fl -join '; '); see the scan skips)" }
                        elseif ($walkCut) { $unsure = $true; "<location path=`"$($e.Location)`"> maps to $($cfg.Sites[$best]), which the scan may not have read in full (it stopped at its time budget)" }
                        else { "<location path=`"$($e.Location)`"> maps to $($cfg.Sites[$best]), where no scanned Idunno.AntiCsrf.dll sits in an application bin folder it applies to" }
                    } else {
                        $unmapped = $true
                        "<location path=`"$($e.Location)`"> maps to $($cfg.Sites[$best]), which is not in the scan"
                    }
                }
                $title = if ($unmapped) { "applicationHost.config registers Idunno.AntiCsrf.AntiCsrfModule for a location TCPK could not map to a scanned folder ($cve)" }
                         elseif ($unsure) { "applicationHost.config registers Idunno.AntiCsrf.AntiCsrfModule, the copy it loads was not fully analysed ($cve)" }
                         else { "applicationHost.config registers Idunno.AntiCsrf.AntiCsrfModule for an application not found in the scan ($cve)" }
                $desc  = ("$($cfg.File) registers Idunno.AntiCsrf.AntiCsrfModule ($(@($maps) -join '; ')). Find the applications it covers and check " +
                    "the copy each one loads (bin\ or the GAC) by hash or IL. The cookie and form field names are set in each application's web.config. $flow")
                $trig = 'cookie and form field names are set in the application web.config'
            } else {
                $pipe  = Format-TcpkIdunnoPipeline -Regs $adds
                $noVal = if ($cfg.NoIntegratedValidation) { ' The same web.config sets validateIntegratedModeConfiguration="false".' } else { '' }
                # The bin\ folder each registration is aimed at: this folder's, or the nested
                # application's when a <location> targets one.
                $cfgKey = ConvertTo-TcpkIdunnoPathKey $cfgDir
                $binDirs = @(@(foreach ($e in $adds) {
                    $dirFor = $cfgDir
                    if ($e.Location -and $e.Location -ne '.') {
                        try {
                            $tgt = [IO.Path]::Combine($cfgDir, ($e.Location -replace '[\\/]', [IO.Path]::DirectorySeparatorChar))
                            if (Test-TcpkIdunnoPathUnder -Child (ConvertTo-TcpkIdunnoPathKey $tgt) -Parent $cfgKey) {
                                $n = Get-TcpkIdunnoNestedAppDir -TargetDir $tgt -RootKey $cfgKey
                                if ($n) { $dirFor = $n }
                            }
                        } catch { }
                    }
                    Join-Path $dirFor 'bin'
                }) | Select-Object -Unique)
                $failedHere = @(foreach ($b in $binDirs) { $fk = ConvertTo-TcpkIdunnoPathKey $b; if ($failed.ContainsKey($fk)) { $failed[$fk] } })
                if ($walkCut) {
                    $title = "web.config registers Idunno.AntiCsrf.AntiCsrfModule, its bin folder not fully scanned ($cve)"
                    $found = "and the scan stopped at its time budget before it read every file, so whether $($binDirs -join ', ') holds an Idunno.AntiCsrf.dll is not known (see the scan skips)."
                } elseif ($failedHere.Count) {
                    $title = "web.config registers Idunno.AntiCsrf.AntiCsrfModule, the Idunno.AntiCsrf.dll in its bin folder could not be analysed ($cve)"
                    $found = "and the Idunno.AntiCsrf.dll TCPK collected there could not be analysed ($($failedHere -join '; '); see the scan skips)."
                } else {
                    $title = "web.config registers Idunno.AntiCsrf.AntiCsrfModule, no Idunno.AntiCsrf.dll in the bin folder it applies to ($cve)"
                    $found = "and no Idunno.AntiCsrf.dll was found in $($binDirs -join ', ')."
                }
                $desc  = ("$($cfg.File) registers Idunno.AntiCsrf.AntiCsrfModule, $found " +
                    "$pipe$noVal Where the app pool's pipeline (not checked by TCPK) loads that section, ASP.NET loads the assembly from bin\ or " +
                    "the GAC. Find that copy and check its hash or IL. $($script:TcpkIdunnoAntiCsrfScope) $flow")
                $trig = Format-TcpkIdunnoAntiCsrfTrigger -Csrf $cfg.Csrf -App $cfg -AppRoot $cfgDir
            }
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'deser.idunno-anticsrf-config' `
                -Severity 'HIGH' -Confidence 'Inferred' -Title $title `
                -File $cfg.File -Evidence "registered: $regText | trigger: $trig" -Description $desc `
                -Cwe @('CWE-502') -Cvss $cvss -Fix $fix -AttributionBasis 'established-footprint'))
        } catch {
            try { Write-TcpkLog -Level WARN -Component 'deser.idunno-anticsrf' -Message "skipped config ${p}: $($_.Exception.Message)" | Out-Null } catch { }
        }
    }

    return [pscustomobject]@{ Findings = $out.ToArray(); Claimed = $claimed }
}

#requires -Version 5.1
# Idunno.AntiCsrf (CVE-2026-131914, MNDT-2026-0048): published-hash identity, IL proof of the
# unkeyed ObjectStateFormatter.Deserialize sink (receiver and argument traced), and the
# module's registration for the DLL's application (applicationHost.config, parent
# web.configs, the application's own web.config, configSource, location scope).
# IL fixtures are written with Mono.Cecil, so the IL shape is exact and no System.Web
# compile is needed. The unread-image and config-only cases need no Cecil.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-idunno-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    $script:add = '<add name="AntiCSRF" type="Idunno.AntiCsrf.AntiCsrfModule, Idunno.AntiCsrf" />'

    # A Cecil-written assembly. Every Idunno shape also gets PagePreRender doing
    # new ObjectStateFormatter().Serialize(null), as the advisory describes, so an unkeyed
    # constructor always exists somewhere and only the traced receiver can prove the sink.
    function script:New-Fixture {
        param(
            [string]$OutPath, [string]$AsmName = 'Idunno.AntiCsrf', [string]$Namespace = 'Idunno.AntiCsrf',
            [ValidateSet('release', 'debug', 'iface', 'field', 'nosource', 'keyed', 'arg', 'gated', 'ldftn', 'serializeonly',
                'dup', 'ternary', 'deadhelper', 'helper', 'callergate', 'reassign', 'macgate', 'initaccessor',
                'refswap', 'refswap2', 'isvalid', 'wrapgate', 'deadpre', 'explicitinit', 'generichelper', 'baseinit',
                'callerisvalid', 'genclass', 'deadiface', 'baseoverride', 'newobjgate', 'reqgate', 'benignhelper')][string]$Shape = 'release',
            [switch]$RefIdunno
        )
        $an  = New-Object Mono.Cecil.AssemblyNameDefinition($AsmName, [version]'0.9.1.0')
        $asm = [Mono.Cecil.AssemblyDefinition]::CreateAssembly($an, $AsmName, [Mono.Cecil.ModuleKind]::Dll)
        $mod = $asm.MainModule
        $ts  = $mod.TypeSystem
        $web = New-Object Mono.Cecil.AssemblyNameReference('System.Web', [version]'4.0.0.0')
        $sys = New-Object Mono.Cecil.AssemblyNameReference('System', [version]'4.0.0.0')
        $mod.AssemblyReferences.Add($web)
        $mod.AssemblyReferences.Add($sys)
        if ($RefIdunno) { $mod.AssemblyReferences.Add((New-Object Mono.Cecil.AssemblyNameReference('Idunno.AntiCsrf', [version]'0.9.1.0'))) }

        $osfT = New-Object Mono.Cecil.TypeReference('System.Web.UI', 'ObjectStateFormatter', $mod, $web)
        $isfT = New-Object Mono.Cecil.TypeReference('System.Web.UI', 'IStateFormatter', $mod, $web)
        $reqT = New-Object Mono.Cecil.TypeReference('System.Web', 'HttpRequest', $mod, $web)
        $nvcT = New-Object Mono.Cecil.TypeReference('System.Collections.Specialized', 'NameValueCollection', $mod, $sys)
        $pspT = New-Object Mono.Cecil.TypeReference('System.Web.UI', 'PageStatePersister', $mod, $web)
        $mk = {
            param($name, $ret, $decl, [object[]]$params = @())
            $r = New-Object Mono.Cecil.MethodReference($name, $ret, $decl)
            $r.HasThis = $true
            foreach ($p in $params) { $r.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($p))) }
            , $r
        }
        $ctor   = & $mk '.ctor' $ts.Void $osfT
        $deser  = & $mk 'Deserialize' $ts.Object $osfT @($ts.String)
        $ideser = & $mk 'Deserialize' $ts.Object $isfT @($ts.String)
        $ser    = & $mk 'Serialize' $ts.String $osfT @($ts.Object)
        $form   = & $mk 'get_Form' $nvcT $reqT
        $item   = & $mk 'get_Item' $ts.String $nvcT @($ts.String)
        $getSf  = & $mk 'get_StateFormatter' $isfT $pspT
        $hmacT  = New-Object Mono.Cecil.TypeReference('System.Security.Cryptography', 'HMACSHA256', $mod, $ts.CoreLibrary)
        $hmacCtor = & $mk '.ctor' $ts.Void $hmacT
        $lib    = New-Object Mono.Cecil.AssemblyNameReference('Lib', [version]'1.0.0.0')
        $optT   = New-Object Mono.Cecil.TypeReference('Lib', 'Options', $mod, $lib)
        $optCtor = & $mk '.ctor' $ts.Void $optT
        $extT   = New-Object Mono.Cecil.TypeReference('System.Runtime.CompilerServices', 'IsExternalInit', $mod, $ts.CoreLibrary)
        $initRet = New-Object Mono.Cecil.RequiredModifierType($extT, $ts.Void)
        $setMode = & $mk 'set_Mode' $initRet $optT @($ts.String)
        $appT   = New-Object Mono.Cecil.TypeReference('System.Web', 'HttpApplication', $mod, $web)
        $ihmT   = New-Object Mono.Cecil.TypeReference('System.Web', 'IHttpModule', $mod, $web)
        $ihmT.IsValueType = $false

        $O = [Mono.Cecil.Cil.OpCodes]
        $static = [Mono.Cecil.MethodAttributes]::Private -bor [Mono.Cecil.MethodAttributes]::Static
        $t = New-Object Mono.Cecil.TypeDefinition($Namespace, 'AntiCsrfModule', ([Mono.Cecil.TypeAttributes]::Public -bor [Mono.Cecil.TypeAttributes]::Class), $ts.Object)
        $mod.Types.Add($t)

        $pr = New-Object Mono.Cecil.MethodDefinition('PagePreRender', $static, $ts.Void)
        $t.Methods.Add($pr)
        $pil = $pr.Body.GetILProcessor()
        $pil.Append($pil.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor))
        $pil.Append($pil.Create($O::Ldnull))
        $pil.Append($pil.Create($O::Callvirt, [Mono.Cecil.MethodReference]$ser))
        $pil.Append($pil.Create($O::Pop))
        $pil.Append($pil.Create($O::Ret))

        $verify = $null
        if ($Shape -eq 'gated') {
            $verify = New-Object Mono.Cecil.MethodDefinition('VerifyMac', $static, $ts.Boolean)
            $verify.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($ts.String)))
            $t.Methods.Add($verify)
            $vil = $verify.Body.GetILProcessor()
            $vil.Append($vil.Create($O::Ldc_I4_1))
            $vil.Append($vil.Create($O::Ret))
        }
        $field = $null
        if ($Shape -eq 'field' -or $Shape -eq 'dup') {
            $field = New-Object Mono.Cecil.FieldDefinition('formatter', ([Mono.Cecil.FieldAttributes]::Private -bor [Mono.Cecil.FieldAttributes]::Static), $osfT)
            $t.Fields.Add($field)
            $finit = New-Object Mono.Cecil.MethodDefinition('InitFormatter', $static, $ts.Void)
            $t.Methods.Add($finit)
            $iil = $finit.Body.GetILProcessor()
            $iil.Append($iil.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor))
            $iil.Append($iil.Create($O::Stsfld, [Mono.Cecil.FieldReference]$field))
            $iil.Append($iil.Create($O::Ret))
        }

        $addMethod = {
            param([string]$name, $ret, [object[]]$ptypes = @())
            $md = New-Object Mono.Cecil.MethodDefinition($name, $static, $ret)
            foreach ($pt in $ptypes) { $md.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($pt))) }
            $t.Methods.Add($md)
            , $md
        }
        # Request.Form["__CSRFTOKEN"] on processor $p (the HttpRequest itself is a null placeholder)
        $emitForm = {
            param($p)
            $p.Append($p.Create($O::Ldnull))
            $p.Append($p.Create($O::Callvirt, [Mono.Cecil.MethodReference]$form))
            $p.Append($p.Create($O::Ldstr, '__CSRFTOKEN'))
            $p.Append($p.Create($O::Callvirt, [Mono.Cecil.MethodReference]$item))
        }
        # new ObjectStateFormatter().Deserialize(Request.Form[...]) on processor $p
        $emitRelease = {
            param($p)
            $p.Append($p.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); & $emitForm $p
            $p.Append($p.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $p.Append($p.Create($O::Pop))
        }
        $readToken = $null
        if (@('deadhelper', 'helper', 'callergate', 'generichelper', 'callerisvalid') -contains $Shape) {
            $readToken = & $addMethod $(if ($Shape -eq 'deadhelper') { 'LegacyReadToken' } else { 'ReadToken' }) $ts.Void
            if ($Shape -eq 'generichelper') { $readToken.GenericParameters.Add((New-Object Mono.Cecil.GenericParameter('T', $readToken))) }
            $rtp = $readToken.Body.GetILProcessor(); & $emitRelease $rtp; $rtp.Append($rtp.Create($O::Ret))
        }
        $isValid = $null
        if ($Shape -eq 'isvalid' -or $Shape -eq 'callerisvalid') {
            # static bool IsValid(string value, string mac): an HMAC check the handler cannot see by name
            $isValid = & $addMethod 'IsValid' $ts.Boolean @($ts.String, $ts.String)
            $ivp = $isValid.Body.GetILProcessor()
            $ivp.Append($ivp.Create($O::Newobj, [Mono.Cecil.MethodReference]$hmacCtor)); $ivp.Append($ivp.Create($O::Pop))
            $ivp.Append($ivp.Create($O::Ldc_I4_1)); $ivp.Append($ivp.Create($O::Ret))
        }
        $swap = $null
        if ($Shape -like 'refswap*') {
            # static void Swap(ref string s) { s = "stored"; }
            $swap = & $addMethod 'Swap' $ts.Void @((New-Object Mono.Cecil.ByReferenceType($ts.String)))
            $swp = $swap.Body.GetILProcessor()
            $swp.Append($swp.Create($O::Ldarg_0)); $swp.Append($swp.Create($O::Ldstr, 'stored'))
            $swp.Append($swp.Create($O::Stind_Ref)); $swp.Append($swp.Create($O::Ret))
        }
        $genRead = $null
        if ($Shape -eq 'genclass') {
            # static class TokenReader<T> { public static void Read() { <sink> } }
            $tr = New-Object Mono.Cecil.TypeDefinition($Namespace, 'TokenReader`1', ([Mono.Cecil.TypeAttributes]::Public -bor [Mono.Cecil.TypeAttributes]::Abstract -bor [Mono.Cecil.TypeAttributes]::Sealed), $ts.Object)
            $tr.GenericParameters.Add((New-Object Mono.Cecil.GenericParameter('T', $tr)))
            $mod.Types.Add($tr)
            $rd = New-Object Mono.Cecil.MethodDefinition('Read', ([Mono.Cecil.MethodAttributes]::Public -bor [Mono.Cecil.MethodAttributes]::Static), $ts.Void)
            $tr.Methods.Add($rd)
            $rdp = $rd.Body.GetILProcessor(); & $emitRelease $rdp; $rdp.Append($rdp.Create($O::Ret))
            $git = New-Object Mono.Cecil.GenericInstanceType($tr)
            $git.GenericArguments.Add($ts.String)
            $genRead = New-Object Mono.Cecil.MethodReference('Read', $ts.Void, $git)
        }
        $tokCtor = $null
        if ($Shape -eq 'newobjgate') {
            # class CsrfToken { public CsrfToken(string value, string tag) { new HMACSHA256(); } }
            $tok = New-Object Mono.Cecil.TypeDefinition($Namespace, 'CsrfToken', ([Mono.Cecil.TypeAttributes]::Public -bor [Mono.Cecil.TypeAttributes]::Class), $ts.Object)
            $mod.Types.Add($tok)
            $tokCtor = New-Object Mono.Cecil.MethodDefinition('.ctor', ([Mono.Cecil.MethodAttributes]::Public -bor [Mono.Cecil.MethodAttributes]::HideBySig -bor [Mono.Cecil.MethodAttributes]::SpecialName -bor [Mono.Cecil.MethodAttributes]::RTSpecialName), $ts.Void)
            $tokCtor.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($ts.String))); $tokCtor.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($ts.String)))
            $tok.Methods.Add($tokCtor)
            $tcp = $tokCtor.Body.GetILProcessor()
            $tcp.Append($tcp.Create($O::Newobj, [Mono.Cecil.MethodReference]$hmacCtor)); $tcp.Append($tcp.Create($O::Pop)); $tcp.Append($tcp.Create($O::Ret))
        }
        $isAuth = $null
        if ($Shape -eq 'reqgate') {
            # static bool IsAuthentic(HttpRequest r): an HMAC check over the request, handed the request object
            $isAuth = & $addMethod 'IsAuthentic' $ts.Boolean @($reqT)
            $iap = $isAuth.Body.GetILProcessor()
            $iap.Append($iap.Create($O::Newobj, [Mono.Cecil.MethodReference]$hmacCtor)); $iap.Append($iap.Create($O::Pop))
            $iap.Append($iap.Create($O::Ldc_I4_1)); $iap.Append($iap.Create($O::Ret))
        }
        $isSup = $null; $raise = $null
        if ($Shape -eq 'benignhelper') {
            # bool IsSuppressed(object page) { page.GetType(); return false; } and void RaiseError(string m) { throw new HttpException(m); }
            $objGetType = New-Object Mono.Cecil.MethodReference('GetType', (New-Object Mono.Cecil.TypeReference('System', 'Type', $mod, $ts.CoreLibrary)), $ts.Object); $objGetType.HasThis = $true
            $isSup = & $addMethod 'IsSuppressed' $ts.Boolean @($ts.Object)
            $isp = $isSup.Body.GetILProcessor()
            $isp.Append($isp.Create($O::Ldarg_0)); $isp.Append($isp.Create($O::Callvirt, [Mono.Cecil.MethodReference]$objGetType)); $isp.Append($isp.Create($O::Pop))
            $isp.Append($isp.Create($O::Ldc_I4_0)); $isp.Append($isp.Create($O::Ret))
            $httpExT = New-Object Mono.Cecil.TypeReference('System.Web', 'HttpException', $mod, $web)
            $httpExCtor = & $mk '.ctor' $ts.Void $httpExT @($ts.String)
            $raise = & $addMethod 'RaiseError' $ts.Void @($ts.String)
            $rep = $raise.Body.GetILProcessor()
            $rep.Append($rep.Create($O::Ldarg_0)); $rep.Append($rep.Create($O::Newobj, [Mono.Cecil.MethodReference]$httpExCtor)); $rep.Append($rep.Create($O::Throw))
        }
        $verifySig = $null
        if ($Shape -eq 'callergate' -or $Shape -eq 'wrapgate') {
            $verifySig = & $addMethod 'VerifySignature' $ts.Boolean @($ts.Object)
            $vsp = $verifySig.Body.GetILProcessor(); $vsp.Append($vsp.Create($O::Ldc_I4_1)); $vsp.Append($vsp.Create($O::Ret))
        }
        $lookup = $null
        if ($Shape -eq 'reassign') {
            $lookup = & $addMethod 'Lookup' $ts.String @($ts.String)
            $lkp = $lookup.Body.GetILProcessor(); $lkp.Append($lkp.Create($O::Ldarg_0)); $lkp.Append($lkp.Create($O::Ret))
        }

        $m = New-Object Mono.Cecil.MethodDefinition('PreRequestHandlerExecute', $static, $ts.Void)
        $m.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($ts.Object)))
        $t.Methods.Add($m)
        $il = $m.Body.GetILProcessor()
        # Request.Form["__CSRFTOKEN"] (the HttpRequest itself is a null placeholder)
        $formValue = {
            $il.Append($il.Create($O::Ldnull))
            $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$form))
            $il.Append($il.Create($O::Ldstr, '__CSRFTOKEN'))
            $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$item))
        }
        $v0 = New-Object Mono.Cecil.Cil.VariableDefinition($osfT)
        $v1 = New-Object Mono.Cecil.Cil.VariableDefinition($ts.String)
        switch ($Shape) {
            'release' {
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'iface' {
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$ideser)); $il.Append($il.Create($O::Pop))
            }
            'debug' {
                $m.Body.Variables.Add($v0); $m.Body.Variables.Add($v1)
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Stloc, $v0))
                & $formValue; $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloc, $v0)); $il.Append($il.Create($O::Ldloc, $v1))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'field' {
                $il.Append($il.Create($O::Ldsfld, [Mono.Cecil.FieldReference]$field)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'nosource' {
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Ldstr, 'x'))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'keyed' {
                $il.Append($il.Create($O::Ldnull)); $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$getSf)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$ideser)); $il.Append($il.Create($O::Pop))
            }
            'arg' {
                $il.Append($il.Create($O::Ldarg_0)); $il.Append($il.Create($O::Castclass, [Mono.Cecil.TypeReference]$osfT)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'gated' {
                $m.Body.Variables.Add($v0); $m.Body.Variables.Add($v1)
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Stloc, $v0))
                & $formValue; $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloc, $v1)); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$verify)); $il.Append($il.Create($O::Pop))
                $il.Append($il.Create($O::Ldloc, $v0)); $il.Append($il.Create($O::Ldloc, $v1))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'ldftn' {
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Ldftn, [Mono.Cecil.MethodReference]$deser))
                $il.Append($il.Create($O::Pop)); $il.Append($il.Create($O::Pop))
            }
            'dup' {
                # (cache = new ObjectStateFormatter()).Deserialize(...): newobj; dup; stsfld
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Dup))
                $il.Append($il.Create($O::Stsfld, [Mono.Cecil.FieldReference]$field)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'ternary' {
                # (flag ? new ObjectStateFormatter() : persister.StateFormatter).Deserialize(...): a join at the receiver
                $newI = $il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)
                $mergeI = $il.Create($O::Ldnull)
                $il.Append($il.Create($O::Ldarg_0)); $il.Append($il.Create($O::Brtrue, [Mono.Cecil.Cil.Instruction]$newI))
                $il.Append($il.Create($O::Ldnull)); $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$getSf))
                $il.Append($il.Create($O::Br, [Mono.Cecil.Cil.Instruction]$mergeI))
                $il.Append($newI); $il.Append($mergeI)
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$form)); $il.Append($il.Create($O::Ldstr, '__CSRFTOKEN'))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$item))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$ideser)); $il.Append($il.Create($O::Pop))
            }
            'deadhelper' {
                # the handler uses the page's keyed formatter; the unkeyed sink sits in a method nothing calls
                $il.Append($il.Create($O::Ldnull)); $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$getSf)); & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$ideser)); $il.Append($il.Create($O::Pop))
            }
            'helper' {
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$readToken))
            }
            'callergate' {
                $il.Append($il.Create($O::Ldarg_0)); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$verifySig)); $il.Append($il.Create($O::Pop))
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$readToken))
            }
            'reassign' {
                # token = Request.Form[f]; token = Lookup(token); formatter.Deserialize(token)
                $m.Body.Variables.Add($v0); $m.Body.Variables.Add($v1)
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Stloc, $v0))
                & $formValue; $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloc, $v1)); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$lookup)); $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloc, $v0)); $il.Append($il.Create($O::Ldloc, $v1))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'macgate' {
                # new HMACSHA256(...) before the sink; the helper name says nothing
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$hmacCtor)); $il.Append($il.Create($O::Pop))
                & $emitRelease $il
            }
            'generichelper' {
                $gim = New-Object Mono.Cecil.GenericInstanceMethod($readToken)
                $gim.GenericArguments.Add($ts.String)
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$gim))
            }
            'isvalid' {
                $m.Body.Variables.Add($v0); $m.Body.Variables.Add($v1)
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Stloc, $v0))
                & $formValue; $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloc, $v1)); $il.Append($il.Create($O::Ldnull))
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$isValid)); $il.Append($il.Create($O::Pop))
                $il.Append($il.Create($O::Ldloc, $v0)); $il.Append($il.Create($O::Ldloc, $v1))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            { $_ -like 'refswap*' } {
                # token = Request.Form[f]; Swap(ref token); [copy = token;] formatter.Deserialize(token or copy)
                $v2 = New-Object Mono.Cecil.Cil.VariableDefinition($ts.String)
                $m.Body.Variables.Add($v0); $m.Body.Variables.Add($v1); $m.Body.Variables.Add($v2)
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Stloc, $v0))
                & $formValue; $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloca, $v1)); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$swap))
                $argVar = $v1
                if ($Shape -eq 'refswap2') { $il.Append($il.Create($O::Ldloc, $v1)); $il.Append($il.Create($O::Stloc, $v2)); $argVar = $v2 }
                $il.Append($il.Create($O::Ldloc, $v0)); $il.Append($il.Create($O::Ldloc, $argVar))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            { @('wrapgate', 'deadpre', 'explicitinit', 'baseinit', 'deadiface', 'baseoverride') -contains $_ } {
                & $emitRelease $il
            }
            'callerisvalid' {
                # IsValid(Request.Form[f], null) in the handler, then ReadToken() holds the sink
                & $formValue; $il.Append($il.Create($O::Ldnull))
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$isValid)); $il.Append($il.Create($O::Pop))
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$readToken))
            }
            'genclass' {
                $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$genRead))
            }
            'newobjgate' {
                $m.Body.Variables.Add($v0); $m.Body.Variables.Add($v1)
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor)); $il.Append($il.Create($O::Stloc, $v0))
                & $formValue; $il.Append($il.Create($O::Stloc, $v1))
                $il.Append($il.Create($O::Ldloc, $v1)); $il.Append($il.Create($O::Ldnull))
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$tokCtor)); $il.Append($il.Create($O::Pop))
                $il.Append($il.Create($O::Ldloc, $v0)); $il.Append($il.Create($O::Ldloc, $v1))
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
            'reqgate' {
                $il.Append($il.Create($O::Ldnull)); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$isAuth)); $il.Append($il.Create($O::Pop))
                & $emitRelease $il
            }
            'benignhelper' {
                # the advisory's flow: suppression check, error raise on the empty case, then the sink
                $il.Append($il.Create($O::Ldarg_0)); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$isSup)); $il.Append($il.Create($O::Pop))
                $il.Append($il.Create($O::Ldstr, 'empty')); $il.Append($il.Create($O::Call, [Mono.Cecil.MethodReference]$raise))
                & $emitRelease $il
            }
            'initaccessor' {
                # new Options { Mode = "x" } between the formatter and the call (init accessor: void modreq(IsExternalInit))
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$ctor))
                $il.Append($il.Create($O::Newobj, [Mono.Cecil.MethodReference]$optCtor)); $il.Append($il.Create($O::Dup))
                $il.Append($il.Create($O::Ldstr, 'x')); $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$setMode)); $il.Append($il.Create($O::Pop))
                & $formValue
                $il.Append($il.Create($O::Callvirt, [Mono.Cecil.MethodReference]$deser)); $il.Append($il.Create($O::Pop))
            }
        }
        $il.Append($il.Create($O::Ret))

        # IHttpModule.Init subscribes the handler (ldftn), as the real module does. ASP.NET runs a
        # module only through Init, so this is what makes the handler reachable.
        $initTarget = $m
        if ($Shape -eq 'wrapgate') {
            # Init wires CheckedHandler, which verifies a signature before calling the handler
            $checked = & $addMethod 'CheckedHandler' $ts.Void @($ts.Object)
            $chp = $checked.Body.GetILProcessor()
            $chp.Append($chp.Create($O::Ldarg_0)); $chp.Append($chp.Create($O::Call, [Mono.Cecil.MethodReference]$verifySig)); $chp.Append($chp.Create($O::Pop))
            $chp.Append($chp.Create($O::Ldarg_0)); $chp.Append($chp.Create($O::Call, [Mono.Cecil.MethodReference]$m)); $chp.Append($chp.Create($O::Ret))
            $initTarget = $checked
        }
        if ($Shape -eq 'deadpre') {
            # Init wires CompareTokens; the old handler with the sink is no longer subscribed
            $cmp = & $addMethod 'CompareTokens' $ts.Void @($ts.Object)
            $cmpp = $cmp.Body.GetILProcessor(); $cmpp.Append($cmpp.Create($O::Ret))
            $initTarget = $cmp
        }
        if ($Shape -eq 'deadiface' -or $Shape -eq 'baseoverride') {
            $cmp = & $addMethod 'CompareTokens' $ts.Void @($ts.Object)
            $cmpp = $cmp.Body.GetILProcessor(); $cmpp.Append($cmpp.Create($O::Ret))
            $initTarget = $cmp
        }
        if ($Shape -eq 'deadiface') {
            # void ILegacyModule.Init(HttpApplication) wires the old handler; ASP.NET never calls it
            $ileg = New-Object Mono.Cecil.TypeDefinition($Namespace, 'ILegacyModule', ([Mono.Cecil.TypeAttributes]::Public -bor [Mono.Cecil.TypeAttributes]::Interface -bor [Mono.Cecil.TypeAttributes]::Abstract))
            $mod.Types.Add($ileg)
            $ilegInit = New-Object Mono.Cecil.MethodDefinition('Init', ([Mono.Cecil.MethodAttributes]::Public -bor [Mono.Cecil.MethodAttributes]::Abstract -bor [Mono.Cecil.MethodAttributes]::Virtual -bor [Mono.Cecil.MethodAttributes]::NewSlot -bor [Mono.Cecil.MethodAttributes]::HideBySig), $ts.Void)
            $ilegInit.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($appT))); $ileg.Methods.Add($ilegInit)
            $legacy = New-Object Mono.Cecil.MethodDefinition("$Namespace.ILegacyModule.Init", ([Mono.Cecil.MethodAttributes]::Private -bor [Mono.Cecil.MethodAttributes]::Virtual -bor [Mono.Cecil.MethodAttributes]::Final -bor [Mono.Cecil.MethodAttributes]::NewSlot -bor [Mono.Cecil.MethodAttributes]::HideBySig), $ts.Void)
            $legacy.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($appT)))
            $legacy.Overrides.Add($ilegInit)
            $t.Methods.Add($legacy)
            $lgp = $legacy.Body.GetILProcessor(); $lgp.Append($lgp.Create($O::Ldftn, [Mono.Cecil.MethodReference]$m)); $lgp.Append($lgp.Create($O::Pop)); $lgp.Append($lgp.Create($O::Ret))
        }
        if ($Shape -eq 'baseoverride') {
            # ModuleBase.Init wires the old handler; AntiCsrfModule.Init overrides it and wires CompareTokens
            $base = New-Object Mono.Cecil.TypeDefinition($Namespace, 'ModuleBase', ([Mono.Cecil.TypeAttributes]::Public -bor [Mono.Cecil.TypeAttributes]::Class -bor [Mono.Cecil.TypeAttributes]::Abstract), $ts.Object)
            $mod.Types.Add($base)
            $t.BaseType = $base
            $binit = New-Object Mono.Cecil.MethodDefinition('Init', ([Mono.Cecil.MethodAttributes]::Public -bor [Mono.Cecil.MethodAttributes]::Virtual -bor [Mono.Cecil.MethodAttributes]::HideBySig -bor [Mono.Cecil.MethodAttributes]::NewSlot), $ts.Void)
            $binit.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($appT))); $base.Methods.Add($binit)
            $bip = $binit.Body.GetILProcessor(); $bip.Append($bip.Create($O::Ldftn, [Mono.Cecil.MethodReference]$m)); $bip.Append($bip.Create($O::Pop)); $bip.Append($bip.Create($O::Ret))
        }
        $owner = $t
        if ($Shape -eq 'baseinit') {
            $base = New-Object Mono.Cecil.TypeDefinition($Namespace, 'ModuleBase', ([Mono.Cecil.TypeAttributes]::Public -bor [Mono.Cecil.TypeAttributes]::Class -bor [Mono.Cecil.TypeAttributes]::Abstract), $ts.Object)
            $mod.Types.Add($base)
            $t.BaseType = $base
            $owner = $base
        }
        $initName = if ($Shape -eq 'explicitinit') { 'System.Web.IHttpModule.Init' } else { 'Init' }
        $init = New-Object Mono.Cecil.MethodDefinition($initName, ([Mono.Cecil.MethodAttributes]::Public -bor [Mono.Cecil.MethodAttributes]::Virtual -bor [Mono.Cecil.MethodAttributes]::HideBySig), $ts.Void)
        $init.Parameters.Add((New-Object Mono.Cecil.ParameterDefinition($appT)))
        if ($Shape -eq 'explicitinit') { $init.Overrides.Add((& $mk 'Init' $ts.Void $ihmT @($appT))) }
        $owner.Methods.Add($init)
        $inp = $init.Body.GetILProcessor()
        $inp.Append($inp.Create($O::Ldftn, [Mono.Cecil.MethodReference]$initTarget)); $inp.Append($inp.Create($O::Pop)); $inp.Append($inp.Create($O::Ret))

        New-Item -ItemType Directory -Path (Split-Path -Parent $OutPath) -Force | Out-Null
        $asm.Write($OutPath)
        $asm.Dispose()
    }

    # 'MZ' ... 'BSJB' ...: passes the managed pre-filter, cannot be read as an assembly.
    function script:New-GarbageDll {
        param([string]$OutPath)
        New-Item -ItemType Directory -Path (Split-Path -Parent $OutPath) -Force | Out-Null
        $b = New-Object byte[] 4096
        $b[0] = 0x4D; $b[1] = 0x5A
        $sig = [Text.Encoding]::ASCII.GetBytes('BSJB')
        [Array]::Copy($sig, 0, $b, 2048, 4)
        [IO.File]::WriteAllBytes($OutPath, $b)
    }

    function script:Write-File {
        param([string]$Path, [string]$Text)
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        [IO.File]::WriteAllText($Path, $Text)
    }

    function script:Cfg {
        param([string]$Modules, [string]$HttpModules, [string]$Body = '', [string]$Ns = '')
        $x = if ($Ns) { " xmlns=`"$Ns`"" } else { '' }
        $s = "<?xml version=`"1.0`"?>`n<configuration$x>`n$Body`n"
        if ($PSBoundParameters.ContainsKey('HttpModules')) { $s += "<system.web><httpModules>$HttpModules</httpModules></system.web>`n" }
        if ($PSBoundParameters.ContainsKey('Modules')) { $s += "<system.webServer><modules>$Modules</modules></system.webServer>`n" }
        return "$s</configuration>"
    }

    # A site folder: optional web.config, and bin\Idunno.AntiCsrf.dll of the given shape.
    function script:New-Site {
        param([string]$Name, [string]$WebConfig, [string]$Shape = 'release', [switch]$Garbage, [switch]$NoDll)
        $root = Join-Path $script:work $Name
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        if ($WebConfig) { Write-File (Join-Path $root 'web.config') $WebConfig }
        $dll = Join-Path (Join-Path $root 'bin') 'Idunno.AntiCsrf.dll'
        if ($Garbage) { New-GarbageDll $dll }
        elseif (-not $NoDll) { New-Fixture -OutPath $dll -Shape $Shape }
        return $root
    }

    function script:Get-Idunno {
        param([string]$Path)
        @(Test-TcpkDeserialization -Path $Path | Where-Object { $_.RuleId -like 'deser.idunno-anticsrf-*' })
    }
    function script:Get-Cvss {
        param($Finding)
        & (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $Finding
    }

    $script:csrf = '<configSections><section name="csrfSettings" type="Idunno.AntiCsrf.Configuration.CsrfSettings, Idunno.AntiCsrf" /></configSections><csrfSettings cookieName="__APPCSRF" formFieldName="__APPTOKEN" detectionResult="RaiseException" />'

    # ---- no Cecil needed -------------------------------------------------------------
    $script:gReg   = New-Site -Name 'g-reg' -WebConfig (Cfg -Modules $script:add) -Garbage
    $script:gNoReg = New-Site -Name 'g-noreg' -Garbage
    $script:cfgOnly = New-Site -Name 'cfg-only' -WebConfig (Cfg -HttpModules $script:add) -NoDll

    if ($script:cecil) {
        $script:siteA = New-Site -Name 'siteA' -WebConfig (Cfg -Modules $script:add -Body $script:csrf)
        $script:shapes = @{}
        foreach ($sh in 'debug', 'iface', 'field', 'nosource', 'keyed', 'arg', 'gated', 'ldftn', 'serializeonly',
                'dup', 'ternary', 'deadhelper', 'helper', 'callergate', 'reassign', 'macgate', 'initaccessor',
                'refswap', 'refswap2', 'isvalid', 'wrapgate', 'deadpre', 'explicitinit', 'generichelper', 'baseinit',
                'callerisvalid', 'genclass', 'deadiface', 'baseoverride', 'newobjgate', 'reqgate', 'benignhelper') {
            $script:shapes[$sh] = New-Site -Name "shape-$sh" -WebConfig (Cfg -Modules $script:add) -Shape $sh
        }
        $script:classicNs = New-Site -Name 'classic-ns' -WebConfig (Cfg -HttpModules $script:add -Ns 'http://schemas.microsoft.com/.NetConfiguration/v2.0')
        $script:classicNoVal = New-Site -Name 'classic-noval' -WebConfig (Cfg -HttpModules $script:add -Body '<system.webServer><validation validateIntegratedModeConfiguration="false" /></system.webServer>')
        $script:commented = New-Site -Name 'commented' -WebConfig (Cfg -Modules "<!-- $($script:add) -->")
        $script:removed = New-Site -Name 'removed' -WebConfig (Cfg -Modules "$($script:add)<remove name=`"AntiCSRF`" />")
        $script:locRemove = New-Site -Name 'loc-remove' -WebConfig (Cfg -Modules $script:add -Body '<location path="api"><system.webServer><modules><remove name="AntiCSRF" /></modules></system.webServer></location>')
        $script:locOnly = New-Site -Name 'loc-only' -WebConfig (Cfg -Body "<location path=`"secure`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
        $script:malformed = New-Site -Name 'malformed' -WebConfig '<configuration><system.webServer><modules><add name="AntiCSRF" type="Idunno.AntiCsrf.AntiCsrfModule, Idunno.AntiCsrf"></modules>'

        # configSource
        $script:cs = New-Site -Name 'configsource' -WebConfig (Cfg -Body '<system.webServer><modules configSource="modules.config" /></system.webServer><csrfSettings configSource="csrf.config" />')
        Write-File (Join-Path $script:cs 'modules.config') "<modules>$($script:add)</modules>"
        Write-File (Join-Path $script:cs 'csrf.config') '<csrfSettings cookieName="__EXTCOOKIE" formFieldName="__EXTFIELD" />'
        $script:csEscape = New-Site -Name 'cs-escape' -WebConfig (Cfg -Body '<system.webServer><modules configSource="..\outside.config" /></system.webServer>')

        # inheritance
        $script:inh = Join-Path $script:work 'inherit'
        Write-File (Join-Path $script:inh 'web.config') (Cfg -Modules $script:add)
        Write-File (Join-Path $script:inh 'child/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:inh 'child/bin/Idunno.AntiCsrf.dll')
        $script:inhOff = Join-Path $script:work 'inherit-off'
        Write-File (Join-Path $script:inhOff 'web.config') (Cfg -Body "<location path=`".`" inheritInChildApplications=`"false`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
        New-Fixture -OutPath (Join-Path $script:inhOff 'child/bin/Idunno.AntiCsrf.dll')
        $script:inhRm = Join-Path $script:work 'inherit-rm'
        Write-File (Join-Path $script:inhRm 'web.config') (Cfg -Modules $script:add)
        Write-File (Join-Path $script:inhRm 'child/web.config') (Cfg -Modules '<remove name="AntiCSRF" />')
        New-Fixture -OutPath (Join-Path $script:inhRm 'child/bin/Idunno.AntiCsrf.dll')
        $script:subFolder = New-Site -Name 'subfolder' -WebConfig (Cfg -Body '<appSettings />')
        Write-File (Join-Path $script:subFolder 'secure/web.config') (Cfg -Modules $script:add)

        # applicationHost.config
        $script:newAppHost = {
            param([string]$Root, [string]$ServerWide, [string]$Locations)
            $sites = ("<system.applicationHost><sites>" +
                "<site name=`"Default Web Site`" id=`"1`"><application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"$Root/inetpub/wwwroot`" /></application>" +
                "<application path=`"/legacy`"><virtualDirectory path=`"/`" physicalPath=`"$Root/inetpub/legacy`" /></application></site>" +
                "<site name=`"SiteB`" id=`"2`"><application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"$Root/inetpub/siteB`" /></application></site>" +
                "</sites></system.applicationHost>")
            $sw = if ($ServerWide) { "<system.webServer><modules>$ServerWide</modules></system.webServer>" } else { '' }
            Write-File (Join-Path $Root 'inetsrv/config/applicationHost.config') "<?xml version=`"1.0`"?><configuration>$sites$sw$Locations</configuration>"
        }
        $script:ah = @{}
        foreach ($case in 'global', 'global-removed', 'other-app', 'this-app') {
            $r = Join-Path $script:work "ah-$case"
            $siteB = Join-Path $r 'inetpub/siteB'
            New-Fixture -OutPath (Join-Path $siteB 'bin/Idunno.AntiCsrf.dll')
            $own = if ($case -eq 'global-removed') { Cfg -Modules '<remove name="AntiCSRF" />' -Body $script:csrf } else { Cfg -Body $script:csrf }
            Write-File (Join-Path $siteB 'web.config') $own
            switch ($case) {
                'global'         { & $script:newAppHost $r $script:add '' }
                'global-removed' { & $script:newAppHost $r $script:add '' }
                'other-app'      { & $script:newAppHost $r '' "<location path=`"Default Web Site/legacy`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>" }
                'this-app'       { & $script:newAppHost $r '' "<location path=`"SiteB`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>" }
            }
            $script:ah[$case] = $r
        }

        # DLL outside bin\ next to a modified bin\ copy without the sink
        $script:outsideBin = New-Site -Name 'outside-bin' -WebConfig (Cfg -Modules $script:add) -Shape 'serializeonly'
        New-Fixture -OutPath (Join-Path $script:outsideBin 'Idunno.AntiCsrf.dll')

        # an application assembly that only references Idunno.AntiCsrf
        $script:consumer = Join-Path $script:work 'consumer'
        New-Fixture -OutPath (Join-Path $script:consumer 'bin/MyWebApp.dll') -AsmName 'MyWebApp' -Namespace 'MyWebApp' -RefIdunno

        # applicationHost.config: site-level <location> and a child application under the site folder
        $script:newAppHost2 = {
            param([string]$Root, [string]$Locations)
            $sites = ("<system.applicationHost><sites><site name=`"Default Web Site`" id=`"1`">" +
                "<application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"$Root/inetpub/wwwroot`" /></application>" +
                "<application path=`"/legacy`"><virtualDirectory path=`"/`" physicalPath=`"$Root/inetpub/wwwroot/legacy`" /></application>" +
                "</site></sites></system.applicationHost>")
            Write-File (Join-Path $Root 'inetsrv/config/applicationHost.config') "<?xml version=`"1.0`"?><configuration>$sites$Locations</configuration>"
        }
        $script:ahChild = Join-Path $script:work 'ah-child'
        & $script:newAppHost2 $script:ahChild "<location path=`"Default Web Site`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>"
        Write-File (Join-Path $script:ahChild 'inetpub/wwwroot/legacy/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:ahChild 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
        $script:ahChildOff = Join-Path $script:work 'ah-child-off'
        & $script:newAppHost2 $script:ahChildOff "<location path=`"Default Web Site`" inheritInChildApplications=`"false`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>"
        Write-File (Join-Path $script:ahChildOff 'inetpub/wwwroot/legacy/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:ahChildOff 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
        $script:ahRootDll = Join-Path $script:work 'ah-rootdll'
        & $script:newAppHost2 $script:ahRootDll "<location path=`"Default Web Site/legacy`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>"
        Write-File (Join-Path $script:ahRootDll 'inetpub/wwwroot/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:ahRootDll 'inetpub/wwwroot/bin/Idunno.AntiCsrf.dll')

        # parent <location path> on an ancestor folder of the application
        $script:locAnc = Join-Path $script:work 'loc-ancestor'
        Write-File (Join-Path $script:locAnc 'web.config') (Cfg -Body "<location path=`"apps`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
        New-Fixture -OutPath (Join-Path $script:locAnc 'apps/child/bin/Idunno.AntiCsrf.dll')

        # validateIntegratedModeConfiguration set by the parent, and overridden by the app
        foreach ($v in 'inherited', 'overridden') {
            $r = Join-Path $script:work "val-$v"
            Write-File (Join-Path $r 'web.config') (Cfg -Body '<system.webServer><validation validateIntegratedModeConfiguration="false" /></system.webServer>')
            $own = if ($v -eq 'overridden') { '<system.webServer><validation validateIntegratedModeConfiguration="true" /></system.webServer>' } else { '' }
            Write-File (Join-Path $r 'child/web.config') (Cfg -HttpModules $script:add -Body $own)
            New-Fixture -OutPath (Join-Path $r 'child/bin/Idunno.AntiCsrf.dll')
        }

        # <clear/> in the child, a nested application's own registration, a config-history snapshot
        $script:clearChild = Join-Path $script:work 'clear-child'
        Write-File (Join-Path $script:clearChild 'web.config') (Cfg -Modules $script:add)
        Write-File (Join-Path $script:clearChild 'child/web.config') (Cfg -Modules '<clear />')
        New-Fixture -OutPath (Join-Path $script:clearChild 'child/bin/Idunno.AntiCsrf.dll')
        $script:nested = New-Site -Name 'nested' -WebConfig (Cfg -Body '<appSettings />')
        Write-File (Join-Path $script:nested 'inner/web.config') (Cfg -Modules $script:add)
        New-Item -ItemType Directory -Path (Join-Path $script:nested 'inner/bin') -Force | Out-Null
        $script:hist = Join-Path $script:work 'cfghistory'
        Write-File (Join-Path $script:hist 'inetpub/history/CFGHISTORY_0000000001/applicationHost.config') "<?xml version=`"1.0`"?><configuration><system.webServer><modules>$($script:add)</modules></system.webServer></configuration>"
        Write-File (Join-Path $script:hist 'inetpub/siteB/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:hist 'inetpub/siteB/bin/Idunno.AntiCsrf.dll')

        # hostile input: a configSource with a character .NET Framework rejects, a site on a missing drive
        $script:badCs = New-Site -Name 'bad-configsource' -WebConfig (Cfg -Body '<system.webServer><modules configSource="mod|ules.config" /></system.webServer>')
        $script:noDrive = Join-Path $script:work 'no-drive'
        Write-File (Join-Path $script:noDrive 'inetsrv/config/applicationHost.config') ("<?xml version=`"1.0`"?><configuration><system.applicationHost><sites><site name=`"Intranet`" id=`"3`">" +
            "<application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"Q:\sites\intranet`" /></application></site></sites></system.applicationHost>" +
            "<location path=`"Intranet/forms`"><system.webServer><modules>$($script:add)</modules></system.webServer></location></configuration>")
        Write-File (Join-Path $script:noDrive 'site/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:noDrive 'site/bin/Idunno.AntiCsrf.dll')

        # two leads under one RuleId / Severity / Confidence with different titles
        $script:mixed = Join-Path $script:work 'mixed'
        New-Fixture -OutPath (Join-Path $script:mixed 'app/bin/Idunno.AntiCsrf.dll')
        New-GarbageDll (Join-Path $script:mixed 'payload/Idunno.AntiCsrf.dll')

        # round 3: merge by configuration level across files
        $script:mergeLvl = Join-Path $script:work 'merge-level'
        Write-File (Join-Path $script:mergeLvl 'web.config') (Cfg -Body '<location path="apps/legacy"><system.webServer><validation validateIntegratedModeConfiguration="false" /></system.webServer></location>')
        Write-File (Join-Path $script:mergeLvl 'apps/web.config') (Cfg -Body '<system.webServer><validation validateIntegratedModeConfiguration="true" /></system.webServer>')
        Write-File (Join-Path $script:mergeLvl 'apps/legacy/web.config') (Cfg -HttpModules $script:add)
        New-Fixture -OutPath (Join-Path $script:mergeLvl 'apps/legacy/bin/Idunno.AntiCsrf.dll')
        # a folder applicationHost.config shows is inside the root application, not an application
        $script:notApp = Join-Path $script:work 'not-app'
        Write-File (Join-Path $script:notApp 'inetsrv/config/applicationHost.config') ("<?xml version=`"1.0`"?><configuration><system.applicationHost><sites><site name=`"Default Web Site`" id=`"1`">" +
            "<application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"$($script:notApp)/inetpub/wwwroot`" /></application></site></sites></system.applicationHost></configuration>")
        Write-File (Join-Path $script:notApp 'inetpub/wwwroot/legacy/web.config') (Cfg -Modules $script:add)
        New-Fixture -OutPath (Join-Path $script:notApp 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
        # <validation> moved out with configSource: readable (false) and missing
        $script:valCs = New-Site -Name 'val-cs' -WebConfig (Cfg -HttpModules $script:add -Body '<system.webServer><validation configSource="validation.config" /></system.webServer>')
        Write-File (Join-Path $script:valCs 'validation.config') '<validation validateIntegratedModeConfiguration="false" />'
        $script:valCsMissing = New-Site -Name 'val-cs-missing' -WebConfig (Cfg -HttpModules $script:add -Body '<system.webServer><validation configSource="validation.config" /></system.webServer>')
        # applicationHost.config whose site path is not the scanned folder
        $script:unmapped = Join-Path $script:work 'unmapped'
        Write-File (Join-Path $script:unmapped 'inetsrv/config/applicationHost.config') ("<?xml version=`"1.0`"?><configuration><system.applicationHost><sites><site name=`"Default Web Site`" id=`"1`">" +
            "<application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"Z:\nowhere\wwwroot`" /></application></site></sites></system.applicationHost>" +
            "<location path=`"Default Web Site`"><system.webServer><modules>$($script:add)</modules></system.webServer></location></configuration>")
        Write-File (Join-Path $script:unmapped 'inetpub/wwwroot/web.config') (Cfg -Body '<appSettings />')
        New-Fixture -OutPath (Join-Path $script:unmapped 'inetpub/wwwroot/bin/Idunno.AntiCsrf.dll')
        # a <location> aimed at a nested application with its own (empty) bin
        $script:nestedLoc = New-Site -Name 'nested-loc' -WebConfig (Cfg -Body "<location path=`"inner`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
        New-Item -ItemType Directory -Path (Join-Path $script:nestedLoc 'inner/bin') -Force | Out-Null
        # two module leads with different reasons in one scan
        $script:reasons = Join-Path $script:work 'reasons'
        Write-File (Join-Path $script:reasons 'web.config') (Cfg -Body "<location path=`"app1`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
        New-Fixture -OutPath (Join-Path $script:reasons 'app1/bin/Idunno.AntiCsrf.dll')
        Write-File (Join-Path $script:reasons 'app2/web.config') (Cfg -HttpModules $script:add -Body '<system.webServer><validation validateIntegratedModeConfiguration="false" /></system.webServer>')
        New-Fixture -OutPath (Join-Path $script:reasons 'app2/bin/Idunno.AntiCsrf.dll')

        # two vulnerable registered applications in one scan
        $script:two = Join-Path $script:work 'two'
        foreach ($n in 'app1', 'app2') {
            Write-File (Join-Path $script:two "$n/web.config") (Cfg -Modules $script:add)
            New-Fixture -OutPath (Join-Path $script:two "$n/bin/Idunno.AntiCsrf.dll")
        }
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch { }
    }
}

Describe 'Idunno.AntiCsrf without Mono.Cecil (CVE-2026-131914)' {
    It 'the three advisory hashes are present' {
        $keys = & (Get-Module TCPK) { @($script:TcpkIdunnoAntiCsrfBuilds.Keys) }
        $keys | Should -Contain 'da1efcfed182597ee946a9ef2895dfdfeab2bdff16855aeef01656d8158ead06'
        $keys | Should -Contain 'c5c994891783453ae85f3ef8efb48592b7c560aeb56f531ee9ea5736518246eb'
        $keys | Should -Contain 'aa7bbad4a7ebc38519955ac65517716569508ee4f61fc2f1276086940501e9bf'
    }

    It 'an unreadable image that is registered is a module HIGH Inferred lead, unscored, would-be 9.3' {
        $f = @(Get-Idunno -Path $script:gReg)
        $f.Count | Should -Be 1
        $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-module'
        $f[0].Severity   | Should -Be 'HIGH'
        $f[0].Confidence | Should -Be 'Inferred'
        $f[0].Evidence   | Should -Match 'IL not read'
        $c = Get-Cvss $f[0]
        $c.Source           | Should -Be 'unscored'
        $c.IfConfirmedScore | Should -Be 9.3
    }

    It 'an unreadable image with no registration is a dll lead that says the sink is not verified' {
        $f = @(Get-Idunno -Path $script:gNoReg)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Title    | Should -Match 'sink not proven'
    }

    It 'a registration with no DLL in its bin folder is a config lead naming that folder' {
        $f = @(Get-Idunno -Path $script:cfgOnly)
        $f.Count | Should -Be 1
        $f[0].RuleId      | Should -Be 'deser.idunno-anticsrf-config'
        $f[0].Confidence  | Should -Be 'Inferred'
        $f[0].File        | Should -Match 'web\.config$'
        $f[0].Description | Should -Match 'was found in .*[\\/]cfg-only[\\/]bin\.'
        $f[0].Title       | Should -Not -Match ': '
    }

    It 'the verify hint is the Idunno one, not the generic deser hint' {
        $h = & (Get-Module TCPK) { Get-TcpkVerifyHint -RuleId 'deser.idunno-anticsrf-module' -File 'C:\site\bin\Idunno.AntiCsrf.dll' }
        $h | Should -Match 'applicationHost\.config'
        # re-runs on the application root, not on bin\, so parent and own registrations are read again
        $h | Should -Match "-Path 'C:[\\/]site'"
        $h | Should -Not -Match 'modified build'
        $h | Should -Match 'does not see a parent web\.config'
    }

    It 'no two Private or Public files define the same top-level function (a later file would silently replace it)' {
        # Private files load in name order, so a helper named like one in an earlier file
        # replaces it for the whole module. This happened once: an IL helper here shadowed
        # _Decompile.ps1's Get-TcpkIlLocalIndex and broke the interprocedural taint prover.
        $root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        $defs = foreach ($f in Get-ChildItem (Join-Path $root 'Private'), (Join-Path $root 'Public') -Recurse -Filter *.ps1) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $top = $ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $n.Parent -is [System.Management.Automation.Language.NamedBlockAst] -and $n.Parent.Parent -eq $ast }, $true)
            foreach ($fd in $top) { [pscustomobject]@{ Name = $fd.Name; File = $f.Name } }
        }
        $dups = @($defs | Group-Object Name | Where-Object Count -gt 1 | ForEach-Object { "$($_.Name): $(($_.Group.File) -join ', ')" })
        $dups | Should -BeNullOrEmpty
    }

    It 'Get-TcpkPeFiles hands the web.config it walks past to -ConfigSink (one walk)' {
        $sink = New-Object 'System.Collections.Generic.List[string]'
        $pes = @(& (Get-Module TCPK) { param($p, $s) Get-TcpkPeFiles -Path $p -ConfigSink $s } $script:gReg $sink)
        $pes.Count | Should -Be 1
        @($sink | Where-Object { $_ -match 'web\.config$' }).Count | Should -Be 1
    }
}

Describe 'Idunno.AntiCsrf IL and configuration (CVE-2026-131914)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
    }

    Context 'IL proof' {
        It 'Release shape + own web.config registration is CRITICAL Confirmed (IL) scored 9.3' {
            $f = @(Get-Idunno -Path $script:siteA)
            $f.Count | Should -Be 1
            $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Severity   | Should -Be 'CRITICAL'
            $f[0].Confidence | Should -Be 'Confirmed (IL)'
            $f[0].Title      | Should -Not -Match ': '
            $f[0].Evidence   | Should -Match 'created at Idunno\.AntiCsrf\.AntiCsrfModule::PreRequestHandlerExecute'
            $f[0].Evidence   | Should -Match 'argument from Request\.Form'
            $f[0].Evidence   | Should -Match 'cookie __APPCSRF, form field __APPTOKEN \(from <csrfSettings> in '
            $c = Get-Cvss $f[0]
            $c.Assurance | Should -Be 'proven'
            $c.Score     | Should -Be 9.3
        }

        It 'states the advisory flow as the advisory''s, and lists what was not checked' {
            $d = (Get-Idunno -Path $script:siteA)[0].Description
            $d | Should -Match 'MNDT-2026-0048 describes the published 0\.9\.1 builds'
            $d | Should -Match 'Not checked by TCPK'
            $d | Should -Match 'checks the field some other way'
        }

        It 'the generic deser.objectstateformatter finding is dropped for the claimed DLL' {
            $all = @(Test-TcpkDeserialization -Path $script:siteA)
            @($all | Where-Object { $_.RuleId -eq 'deser.objectstateformatter' }).Count | Should -Be 0
        }

        It '<_> shape is proven (local, interface call, field, dup, helper, explicit or inherited Init, generic helpers, plain-read helpers)' -ForEach @('debug', 'iface', 'field', 'dup', 'helper', 'explicitinit', 'baseinit', 'generichelper', 'genclass', 'benignhelper') {
            $f = @(Get-Idunno -Path $script:shapes[$_])
            $f.Count | Should -Be 1
            $f[0].Severity   | Should -Be 'CRITICAL'
            $f[0].Confidence | Should -Be 'Confirmed (IL)'
        }

        It '<Shape> shape is a HIGH Inferred lead, not Confirmed (IL)' -ForEach @(
            @{ Shape = 'nosource'; Why = 'argument not traced' }
            @{ Shape = 'keyed';    Why = 'get_StateFormatter' }
            @{ Shape = 'arg';      Why = 'ldarg' }
            @{ Shape = 'gated';    Why = 'VerifyMac' }
            @{ Shape = 'ldftn';    Why = 'ldftn' }
            @{ Shape = 'ternary';    Why = 'receiver not traced' }
            @{ Shape = 'deadhelper'; Why = 'request path' }
            @{ Shape = 'callergate'; Why = 'request path' }
            @{ Shape = 'reassign';   Why = 'argument not traced' }
            @{ Shape = 'macgate';    Why = 'HMACSHA256' }
            @{ Shape = 'isvalid';    Why = 'IsValid' }
            @{ Shape = 'refswap';    Why = 'argument not traced' }
            @{ Shape = 'refswap2';   Why = 'argument not traced' }
            @{ Shape = 'wrapgate';   Why = 'request path' }
            @{ Shape = 'deadpre';    Why = 'request path' }
            @{ Shape = 'callerisvalid'; Why = 'IsValid' }
            @{ Shape = 'deadiface';     Why = 'request path' }
            @{ Shape = 'baseoverride';  Why = 'request path' }
            @{ Shape = 'newobjgate';    Why = 'CsrfToken' }
            @{ Shape = 'reqgate';       Why = 'IsAuthentic' }
        ) {
            $f = @(Get-Idunno -Path $script:shapes[$Shape])
            $f.Count | Should -Be 1
            $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Severity   | Should -Be 'HIGH'
            $f[0].Confidence | Should -Be 'Inferred'
            $f[0].Evidence   | Should -Match $Why
            (Get-Cvss $f[0]).Source | Should -Be 'unscored'
        }

        It 'a build that only serializes is INFO Likely-FP (IL) and names the ctor site' {
            $f = @(Get-Idunno -Path $script:shapes['serializeonly'])
            $f.Count | Should -Be 1
            $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Severity   | Should -Be 'INFO'
            $f[0].Confidence | Should -Be 'Likely-FP (IL)'
            $f[0].Evidence   | Should -Match 'PagePreRender'
            $f[0].Fix        | Should -Not -Match 'rotate'
        }

        It 'an init accessor between the formatter and the call keeps the receiver traced (void modreq stack effect)' {
            $dll = Join-Path (Join-Path $script:shapes['initaccessor'] 'bin') 'Idunno.AntiCsrf.dll'
            $r = & (Get-Module TCPK) { param($d) Get-TcpkIdunnoAntiCsrfIl -DllPath $d } $dll
            $site = @($r.Sites | Where-Object { $_.Where -match 'PreRequestHandlerExecute' })
            $site.Count | Should -Be 1
            $site[0].ReceiverOk | Should -BeTrue
            $site[0].Source     | Should -Be 'Request.Form[...]'
        }

        It 'a build that defines no Idunno.AntiCsrf.AntiCsrfModule is a lead even when registered' {
            $root = Join-Path $script:work 'othertype'
            Write-File (Join-Path $root 'web.config') (Cfg -Modules $script:add)
            New-Fixture -OutPath (Join-Path $root 'bin/Idunno.AntiCsrf.dll') -Namespace 'Other'
            $f = @(Get-Idunno -Path $root)
            $f.Count | Should -Be 1
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Evidence | Should -Match 'defines no Idunno\.AntiCsrf\.AntiCsrfModule'
        }

        It 'a published SHA-256 makes it Confirmed and names the build' {
            $dll = Join-Path (Join-Path $script:shapes['nosource'] 'bin') 'Idunno.AntiCsrf.dll'
            $sha = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
            & (Get-Module TCPK) { param($h) $script:TcpkIdunnoAntiCsrfBuilds[$h] = 'test build' } $sha
            try {
                $f = @(Get-Idunno -Path $script:shapes['nosource'])
                $f[0].Severity   | Should -Be 'CRITICAL'
                $f[0].Confidence | Should -Be 'Confirmed'
                $f[0].Evidence   | Should -Match "SHA-256 $sha is the published test build"
            } finally {
                & (Get-Module TCPK) { param($h) $script:TcpkIdunnoAntiCsrfBuilds.Remove($h) } $sha
            }
        }

        It 'with Cecil unavailable a registered DLL is a HIGH Inferred lead' {
            Mock -ModuleName TCPK Initialize-TcpkCecil { $false }
            $f = @(Get-Idunno -Path $script:siteA)
            $f.Count | Should -Be 1
            $f[0].Severity   | Should -Be 'HIGH'
            $f[0].Confidence | Should -Be 'Inferred'
            $f[0].Evidence   | Should -Match 'IL not read'
        }

        It 'an app assembly that only references Idunno.AntiCsrf is not the library (precision)' {
            @(Get-Idunno -Path $script:consumer).Count | Should -Be 0
            @(Test-TcpkDeserialization -Path $script:consumer | Where-Object { $_.RuleId -eq 'deser.objectstateformatter' }).Count | Should -Be 1
        }

        It 'the scanned DLL can be deleted right after the scan (no handle kept)' {
            $copy = Join-Path $script:work 'handle'
            New-Fixture -OutPath (Join-Path $copy 'bin/Idunno.AntiCsrf.dll')
            $null = Get-Idunno -Path $copy
            { Remove-Item -LiteralPath (Join-Path $copy 'bin/Idunno.AntiCsrf.dll') -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context 'web.config semantics' {
        It 'classic httpModules under a namespaced configuration root is CRITICAL with the Classic-only pipeline note' {
            $f = @(Get-Idunno -Path $script:classicNs)
            $f[0].Severity    | Should -Be 'CRITICAL'
            $f[0].Description | Should -Match 'only in system\.web/httpModules'
            $f[0].Evidence    | Should -Match 'form field RaiseException'
        }

        It 'httpModules-only with validateIntegratedModeConfiguration false is a lead' {
            $f = @(Get-Idunno -Path $script:classicNoVal)
            $f[0].Severity    | Should -Be 'HIGH'
            $f[0].Confidence  | Should -Be 'Inferred'
            $f[0].Description | Should -Match 'validateIntegratedModeConfiguration'
        }

        It 'a commented-out add element is not a registration' {
            $f = @(Get-Idunno -Path $script:commented)
            $f.Count | Should -Be 1
            $f[0].RuleId | Should -Be 'deser.idunno-anticsrf-dll'
            (Get-Cvss $f[0]).IfConfirmedScore | Should -Be 9.3
        }

        It 'remove after add in the same collection undoes the registration' {
            $f = @(Get-Idunno -Path $script:removed)
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'removed by'
        }

        It 'a remove inside a location element does not undo the root registration' {
            (Get-Idunno -Path $script:locRemove)[0].Severity | Should -Be 'CRITICAL'
        }

        It 'a registration only under location path secure is a lead, not CRITICAL (modules load per application)' {
            $f = @(Get-Idunno -Path $script:locOnly)
            $f.Count | Should -Be 1
            $f[0].RuleId      | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Severity    | Should -Be 'HIGH'
            $f[0].Description | Should -Match 'below the application level'
            $f[0].Description | Should -Match 'Registrations of AntiCsrfModule sit below the application'
            $f[0].Evidence    | Should -Match '<location path="secure">'
            $f[0].Evidence    | Should -Not -Match 'only for requests'
        }

        It 'a scan pointed at bin still reads the application web.config one level up' {
            (Get-Idunno -Path (Join-Path $script:siteA 'bin'))[0].Severity | Should -Be 'CRITICAL'
        }

        It 'a malformed web.config is reported as not read, not as no registration' {
            $f = @(Get-Idunno -Path $script:malformed)
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'not read: .*XML parse failed'
        }

        It 'configSource modules and csrfSettings are followed' {
            $f = @(Get-Idunno -Path $script:cs)
            $f[0].Severity | Should -Be 'CRITICAL'
            $f[0].Evidence | Should -Match 'configSource .*modules\.config'
            $f[0].Evidence | Should -Match 'cookie __EXTCOOKIE, form field __EXTFIELD'
        }

        It 'a configSource that escapes the folder is refused and reported' {
            $f = @(Get-Idunno -Path $script:csEscape)
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'not a relative path below'
        }

        It 'a parent web.config registration reaches a nested application as a lead, with no contradicting config finding' {
            $f = @(Get-Idunno -Path $script:inh)
            $f.Count | Should -Be 1
            $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Confidence | Should -Be 'Inferred'
            $f[0].Evidence   | Should -Match 'inherited from'
        }

        It 'inheritInChildApplications false stops the parent registration' {
            $f = @(Get-Idunno -Path $script:inhOff)
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count    | Should -Be 1
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' }).Count | Should -Be 1
        }

        It 'a child web.config remove undoes the inherited registration' {
            $f = @(Get-Idunno -Path $script:inhRm)
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'removed by'
        }

        It 'a sub-folder web.config registration is a lead for the application, with no contradicting config finding' {
            $f = @(Get-Idunno -Path $script:subFolder)
            $f.Count | Should -Be 1
            $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Confidence | Should -Be 'Inferred'
        }

        It 'a copy outside bin is not paired with the web.config; the bin copy without the sink is INFO' {
            $f = @(Get-Idunno -Path $script:outsideBin)
            $out = @($f | Where-Object { $_.File -notmatch '[\\/]bin[\\/]' })
            $out.Count       | Should -Be 1
            $out[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $out[0].Severity | Should -Be 'HIGH'
            $out[0].Title    | Should -Match 'outside a bin folder'
            @($f | Where-Object { $_.Severity -eq 'CRITICAL' }).Count | Should -Be 0
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' }).Count | Should -Be 0
        }

        It 'a parent location on an ancestor folder of the application applies to it (inherited)' {
            $f = @(Get-Idunno -Path $script:locAnc)
            $f.Count | Should -Be 1
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Evidence | Should -Match 'inherited from'
        }

        It 'validateIntegratedModeConfiguration false inherited from the parent makes an httpModules-only app a lead' {
            $f = @(Get-Idunno -Path (Join-Path $script:work 'val-inherited'))
            $f[0].Severity    | Should -Be 'HIGH'
            $f[0].Description | Should -Match 'validateIntegratedModeConfiguration'
        }

        It 'the app setting validateIntegratedModeConfiguration true overrides the parent' {
            (Get-Idunno -Path (Join-Path $script:work 'val-overridden'))[0].Severity | Should -Be 'CRITICAL'
        }

        It 'clear in the child web.config removes the inherited registration' {
            $f = @(Get-Idunno -Path $script:clearChild)
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'cleared by'
        }

        It 'a nested application''s own registration is not the outer application''s' {
            $f = @(Get-Idunno -Path $script:nested)
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count    | Should -Be 1
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' }).Count | Should -Be 1
        }

        It 'configuration merges by level across files: a deeper location in a shallower file wins' {
            $f = @(Get-Idunno -Path $script:mergeLvl)
            $f.Count | Should -Be 1
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Title    | Should -Match 'Integrated validation off'
        }

        It 'validation moved out with configSource is followed' {
            $f = @(Get-Idunno -Path $script:valCs)
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Title    | Should -Match 'Integrated validation off'
        }

        It 'validation configSource that cannot be read makes an httpModules-only app a lead' {
            $f = @(Get-Idunno -Path $script:valCsMissing)
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Title    | Should -Match 'Integrated validation setting not read'
        }

        It 'a location aimed at a nested application names that application''s bin folder' {
            $f = @(Get-Idunno -Path $script:nestedLoc)
            $cfg = @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' })
            $cfg.Count | Should -Be 1
            $cfg[0].Description | Should -Match 'was found in .*[\\/]nested-loc[\\/]inner[\\/]bin\.'
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count | Should -Be 1
        }

        It 'a relative -Path resolves against the PowerShell location' {
            Push-Location $script:work
            try { $f = @(Get-Idunno -Path 'inherit') } finally { Pop-Location }
            $f.Count | Should -Be 1
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Evidence | Should -Match 'inherited from'
        }

        It 'a configSource with an invalid path character is reported as not read, without an error' {
            { $null = Test-TcpkDeserialization -Path $script:badCs -ErrorAction Stop } | Should -Not -Throw
            $f = @(Get-Idunno -Path $script:badCs)
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'not read: .*configSource'
            $f[0].Title    | Should -Match 'registration unknown'
        }
    }

    Context 'applicationHost.config' {
        It 'a server-wide registration is a lead, not CRITICAL, and reads the trigger from the app web.config' {
            $f = @(Get-Idunno -Path $script:ah['global'])
            $f.Count | Should -Be 1
            $f[0].RuleId     | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Severity   | Should -Be 'HIGH'
            $f[0].Evidence   | Should -Match 'applicationHost\.config \(server-wide\)'
            $f[0].Evidence   | Should -Match 'cookie __APPCSRF, form field __APPTOKEN'
        }

        It 'the application web.config remove undoes a server-wide registration' {
            $f = @(Get-Idunno -Path $script:ah['global-removed'])
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
            $f[0].Evidence | Should -Match 'removed by'
        }

        It 'a location for another application does not attach to this DLL' {
            $f = @(Get-Idunno -Path $script:ah['other-app'])
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count | Should -Be 1
            $cfg = @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' })
            $cfg.Count       | Should -Be 1
            $cfg[0].Title    | Should -Match '^applicationHost\.config registers'
        }

        It 'a site-level location reaches a child application under the site (inherited)' {
            $f = @(Get-Idunno -Path $script:ahChild)
            $f.Count | Should -Be 1
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Evidence | Should -Match '<location path="Default Web Site">'
        }

        It 'inheritInChildApplications false on the site location keeps it off the child application' {
            $f = @(Get-Idunno -Path $script:ahChildOff)
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count    | Should -Be 1
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' }).Count | Should -Be 1
        }

        It 'a location on a child application is not a sub-path of the root application' {
            $f = @(Get-Idunno -Path $script:ahRootDll)
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count    | Should -Be 1
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-module' }).Count | Should -Be 0
        }

        It 'config-history snapshots are not the running configuration' {
            $f = @(Get-Idunno -Path $script:hist)
            $f.Count | Should -Be 1
            $f[0].RuleId | Should -Be 'deser.idunno-anticsrf-dll'
        }

        It 'a site on a drive that does not exist here raises no error' {
            { $null = Test-TcpkDeserialization -Path $script:noDrive -ErrorAction Stop } | Should -Not -Throw
            $f = @(Get-Idunno -Path $script:noDrive)
            # the site's DLL has no registration; the Intranet/forms registration has no DLL in the scan
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count    | Should -Be 1
            @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' }).Count | Should -Be 1
        }

        It 'a folder applicationHost.config shows is not an application is a lead, not CRITICAL' {
            $f = @(Get-Idunno -Path $script:notApp)
            $f.Count | Should -Be 1
            $f[0].Severity | Should -Be 'HIGH'
            $f[0].Title    | Should -Match 'not an IIS application'
            $f[0].Evidence | Should -Match 'not an application'
            $f[0].Description | Should -Match 'A config TCPK read registers AntiCsrfModule for the folder'
            $f[0].Description | Should -Not -Match 'applies to the application at'
        }

        It 'a location TCPK cannot map to the scanned folder is named, and the config lead says so' {
            $f = @(Get-Idunno -Path $script:unmapped)
            $dll = @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' })
            $dll.Count | Should -Be 1
            $dll[0].Evidence | Should -Match 'not related'
            $dll[0].Title    | Should -Match 'no registration TCPK could relate'
            $dll[0].Description | Should -Not -Match 'that TCPK read applies'
            $cfg = @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' })
            $cfg.Count | Should -Be 1
            $cfg[0].Title | Should -Match 'could not map'
        }

        It 'a location that maps to this application through sites is a lead for it' {
            $f = @(Get-Idunno -Path $script:ah['this-app'])
            $f.Count | Should -Be 1
            $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-module'
            $f[0].Severity | Should -Be 'HIGH'
        }
    }

    Context 'pipeline integration' {
        It 'Confirm-TcpkDeserialization passes the finding through unchanged' {
            $f = (Get-Idunno -Path $script:siteA)[0]
            $before = $f.Description
            $out = $f | Confirm-TcpkDeserialization
            $out.Confidence  | Should -Be 'Confirmed (IL)'
            $out.Description | Should -Be $before
        }

        It 'Resolve-TcpkFindings keeps each registered application as its own finding with its own evidence' {
            $f = @(Get-Idunno -Path $script:two)
            $f.Count | Should -Be 2
            $agg = @($f | Resolve-TcpkFindings -AggregateOnly)
            $agg.Count | Should -Be 2
            $agg = @([pscustomobject]@{ Evidence = (@($agg | ForEach-Object { $_.Evidence }) -join ' | ') })
            # the per-site proof survives, not only the file list
            $agg[0].Evidence | Should -Match 'created at Idunno\.AntiCsrf\.AntiCsrfModule::PreRequestHandlerExecute'
            $agg[0].Evidence | Should -Match 'registered: [^|]*app1[\\/]web\.config'
            $agg[0].Evidence | Should -Match 'registered: [^|]*app2[\\/]web\.config'
        }

        It 'aggregation keeps leads with different titles apart' {
            $f = @(Get-Idunno -Path $script:mixed)
            $f.Count | Should -Be 2
            @($f | Resolve-TcpkFindings -AggregateOnly).Count | Should -Be 2
        }

        It 'module leads with different reasons get different titles and stay apart' {
            $f = @(Get-Idunno -Path $script:reasons | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-module' })
            $f.Count | Should -Be 2
            @($f | ForEach-Object { $_.Title } | Select-Object -Unique).Count | Should -Be 2
            @($f | Resolve-TcpkFindings -AggregateOnly).Count | Should -Be 2
        }

        It 'an expired check budget does not make the Idunno pass skip a DLL the walk already collected' {
            $dll = Get-Item -LiteralPath (Join-Path (Join-Path $script:siteA 'bin') 'Idunno.AntiCsrf.dll')
            $res = & (Get-Module TCPK) {
                param($site, $dll)
                $script:TcpkCheckDeadline = (Get-Date).AddSeconds(-1)
                try { Get-TcpkIdunnoAntiCsrfFindings -Path $site -Candidates @($dll) -ConfigPaths @((Join-Path $site 'web.config')) }
                finally { $script:TcpkCheckDeadline = $null }
            } $script:siteA $dll
            @($res.Findings).Count | Should -Be 1
            $res.Findings[0].Severity | Should -Be 'CRITICAL'
        }

        It 'when the PE walk stopped at the budget, the config lead does not claim the DLL is absent' {
            & (Get-Module TCPK) { $script:TcpkCheckDeadline = (Get-Date).AddSeconds(-1) }
            try { $f = @(Get-Idunno -Path $script:siteA) } finally { & (Get-Module TCPK) { $script:TcpkCheckDeadline = $null } }
            $cfg = @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' })
            $cfg.Count | Should -Be 1
            $cfg[0].Title       | Should -Match 'not fully scanned'
            $cfg[0].Description | Should -Not -Match 'no Idunno\.AntiCsrf\.dll was found'
        }

        It 'a deadline that passes after a complete walk does not make the config lead claim a cut scan' {
            $res = & (Get-Module TCPK) {
                param($site)
                $script:TcpkCheckDeadline = (Get-Date).AddSeconds(-1)
                try { Get-TcpkIdunnoAntiCsrfFindings -Path $site -Candidates @() -ConfigPaths @((Join-Path $site 'web.config')) }
                finally { $script:TcpkCheckDeadline = $null }
            } $script:cfgOnly
            @($res.Findings).Count | Should -Be 1
            $res.Findings[0].Title | Should -Match 'no Idunno\.AntiCsrf\.dll in the bin folder it applies to'
        }

        It 'an applicationHost.config lead does not deny a DLL whose analysis failed' {
            Mock -ModuleName TCPK Get-TcpkIdunnoAntiCsrfIl { throw 'simulated failure' }
            $f = @(Get-Idunno -Path $script:ah['global'])
            $cfg = @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' })
            $cfg.Count | Should -Be 1
            $cfg[0].Title | Should -Match 'not fully analysed'
        }

        It 'a candidate whose analysis fails is not reported as absent by the config finding' {
            Mock -ModuleName TCPK Get-TcpkIdunnoAntiCsrfIl { throw 'simulated failure' }
            $f = @(Get-Idunno -Path $script:siteA)
            $f.Count | Should -Be 1
            $f[0].RuleId      | Should -Be 'deser.idunno-anticsrf-config'
            $f[0].Title       | Should -Match 'could not be analysed'
            $f[0].Description | Should -Not -Match 'no Idunno\.AntiCsrf\.dll was found'
        }

        It 'the LLM judge does not re-rate an Idunno lead' {
            Mock -ModuleName TCPK Test-TcpkLlmAvailable { $true }
            Mock -ModuleName TCPK Get-TcpkMethodIl { throw 'IL must not be extracted for an Idunno finding' }
            Mock -ModuleName TCPK Invoke-TcpkLlmSkepticVote { throw 'the model must not be asked about an Idunno finding' }
            $lead = (Get-Idunno -Path $script:commented)[0]
            $out = @($lead | Invoke-TcpkLlmCodeJudgment -WarningAction SilentlyContinue)
            $out.Count         | Should -Be 1
            $out[0].Confidence | Should -Be 'Inferred'
            Should -Invoke -ModuleName TCPK Get-TcpkMethodIl -Times 0 -Exactly
        }
    }
}

Describe 'Idunno.AntiCsrf config-chain pins' {
    BeforeAll {
        if ($script:cecil) {
            $script:valOff = '<system.webServer><validation validateIntegratedModeConfiguration="false" /></system.webServer>'
            # child-application <remove> written before the site <add> (IIS merges by path depth)
            $script:pDepth = Join-Path $script:work 'pin-depth'
            & $script:newAppHost2 $script:pDepth ("<location path=`"Default Web Site/legacy`"><system.webServer><modules><remove name=`"AntiCSRF`" /></modules></system.webServer></location>" +
                "<location path=`"Default Web Site`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
            Write-File (Join-Path $script:pDepth 'inetpub/wwwroot/legacy/web.config') (Cfg -Body '<appSettings />')
            New-Fixture -OutPath (Join-Path $script:pDepth 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
            # exact application location with inheritInChildApplications="false"
            $script:pExact = Join-Path $script:work 'pin-exact-off'
            & $script:newAppHost2 $script:pExact "<location path=`"Default Web Site/legacy`" inheritInChildApplications=`"false`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>"
            Write-File (Join-Path $script:pExact 'inetpub/wwwroot/legacy/web.config') (Cfg -Body '<appSettings />')
            New-Fixture -OutPath (Join-Path $script:pExact 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
            # parent web.config <location path="apps" inheritInChildApplications="false">
            $script:pAncOff = Join-Path $script:work 'pin-anc-off'
            Write-File (Join-Path $script:pAncOff 'web.config') (Cfg -Body "<location path=`"apps`" inheritInChildApplications=`"false`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>")
            New-Fixture -OutPath (Join-Path $script:pAncOff 'apps/child/bin/Idunno.AntiCsrf.dll')
            # applicationHost.config validation false server-wide, app registers httpModules only
            $script:pAhVal = Join-Path $script:work 'pin-ah-val'
            & $script:newAppHost2 $script:pAhVal $script:valOff
            Write-File (Join-Path $script:pAhVal 'inetpub/wwwroot/legacy/web.config') (Cfg -HttpModules $script:add)
            New-Fixture -OutPath (Join-Path $script:pAhVal 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
            # app web.config validation false only under <location path="api">
            $script:pValApi = New-Site -Name 'pin-val-api' -WebConfig (Cfg -HttpModules $script:add -Body "<location path=`"api`">$($script:valOff)</location>")
        }
    }
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
    }

    It 'a child-application remove written before the site add still undoes it (merge by path depth)' {
        $f = @(Get-Idunno -Path $script:pDepth)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
        $f[0].Evidence | Should -Match 'removed by'
    }
    It 'an exact application location applies even with inheritInChildApplications false' {
        $f = @(Get-Idunno -Path $script:pExact)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-module'
        $f[0].Severity | Should -Be 'HIGH'
    }
    It 'a parent location on an ancestor folder with inheritInChildApplications false does not reach the application' {
        $f = @(Get-Idunno -Path $script:pAncOff)
        @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-dll' }).Count    | Should -Be 1
        @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-config' }).Count | Should -Be 1
        @($f | Where-Object { $_.RuleId -eq 'deser.idunno-anticsrf-module' }).Count | Should -Be 0
    }
    It 'validateIntegratedModeConfiguration false in applicationHost.config makes an httpModules-only app a lead' {
        $f = @(Get-Idunno -Path $script:pAhVal)
        $f.Count | Should -Be 1
        $f[0].Severity   | Should -Be 'HIGH'
        $f[0].Confidence | Should -Be 'Inferred'
    }
    It 'validateIntegratedModeConfiguration false only under a location sub-path does not demote' {
        $f = @(Get-Idunno -Path $script:pValApi)
        $f[0].Severity   | Should -Be 'CRITICAL'
        $f[0].Confidence | Should -Be 'Confirmed (IL)'
    }
    It 'a folder that is a virtual directory of an application is not an application' {
        $root = Join-Path $script:work 'pin-vdir'
        Write-File (Join-Path $root 'inetsrv/config/applicationHost.config') ("<?xml version=`"1.0`"?><configuration><system.applicationHost><sites><site name=`"Default Web Site`" id=`"1`">" +
            "<application path=`"/`"><virtualDirectory path=`"/`" physicalPath=`"$root/inetpub/wwwroot`" /><virtualDirectory path=`"/legacy`" physicalPath=`"$root/inetpub/legacyvd`" /></application>" +
            "</site></sites></system.applicationHost></configuration>")
        Write-File (Join-Path $root 'inetpub/legacyvd/web.config') (Cfg -Modules $script:add)
        New-Fixture -OutPath (Join-Path $root 'inetpub/legacyvd/bin/Idunno.AntiCsrf.dll')
        $f = @(Get-Idunno -Path $root)
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Evidence | Should -Match 'virtual directory'
    }
    It 'at the same configuration level the application web.config merges after applicationHost.config' {
        $root = Join-Path $script:work 'pin-rank'
        & $script:newAppHost2 $root "<location path=`"Default Web Site/legacy`"><system.webServer><modules>$($script:add)</modules></system.webServer></location>"
        Write-File (Join-Path $root 'inetpub/wwwroot/legacy/web.config') (Cfg -Modules '<remove name="AntiCSRF" />')
        New-Fixture -OutPath (Join-Path $root 'inetpub/wwwroot/legacy/bin/Idunno.AntiCsrf.dll')
        $f = @(Get-Idunno -Path $root)
        $f[0].RuleId   | Should -Be 'deser.idunno-anticsrf-dll'
        $f[0].Evidence | Should -Match 'removed by'
    }
    It 'a malformed web.config lead does not say no web.config was found' {
        $f = @(Get-Idunno -Path $script:malformed)
        $f[0].Title       | Should -Match 'registration unknown'
        $f[0].Description | Should -Not -Match 'No web\.config was found'
    }
}

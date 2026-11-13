# Signal extraction and role classification for Test-TcpkAiInferenceServer.
#
# THE QUESTION. Does the audited target SHIP a local LLM inference server (an HTTP listener
# for a model API), and how is it bound? Three roles look alike in a string scan and must
# not be confused:
#
#   server          a listener for a model API. This is the only role that is a finding.
#   engine library  tensor / model-runtime code loaded into the application's own process.
#                   It opens no socket. Inventory only.
#   client          code that names a provider or holds the address of an inference server
#                   that is installed separately. Context only.
#
# WHY A PRODUCT NAME PROVES NOTHING. The first version of this check treated any engine name
# as a server. A provider drop-down ("ollama (local)", "LM Studio"), a 4-character token
# matched in compressed bytes, and a REST path such as /api/chat in an unrelated product all
# produced "bundled inference server" at MEDIUM. A name is used here for two things only: to
# print the product of a port, and to tie port 11434, which a single product uses. For 1234,
# 1337, 3001 and 4891, which are also ordinary development ports, a name ties nothing: a
# provider list plus an unrelated listener on 3001 is not an inference server.
#
# WHY A SENTENCE PROVES NOTHING. A client that tells its user "set OLLAMA_HOST=0.0.0.0 and
# restart" or "run llama-server --host 0.0.0.0" holds the same characters as a launcher
# that does it. Every engine bind form is therefore checked for its surroundings: an
# assignment or a command line stands on its own, a sentence has words on either side.
# See Test-TcpkAiProseLeft / Test-TcpkAiProseRight / Test-TcpkAiArgRun.
#
# WHAT ESTABLISHES A SERVER (any one, per file):
#   1. the file IS a known engine server binary (matched on the file name);
#   2. an engine bind setting: the engine's host variable assigned an all-interfaces address,
#      or the engine's server on a command line with its host / port flag -- as an
#      assignment or a command, never as part of a sentence. How strict the form must be
#      depends on the file type (see Get-TcpkAiEnvTier);
#   3. two or more distinct model API routes matched as whole tokens, an engine marker, and a
#      router-side path parameter (/v1/models/:model). The path parameter is the part a
#      client does not carry: a client builds the path from a value, a router declares the
#      placeholder;
#   4. a route registration call written in a server-only syntax with a model API route as
#      its literal argument (MapPost("/v1/chat/completions"), app.post(...), a decorator);
#   5. in a compiled .NET assembly, where the call name and the route are held in different
#      heaps and rule 4 cannot match: a route-mapping member name (MapPost, MapGet, ...) and
#      two or more model API routes that are each a whole string literal;
#   6. port 11434 in a listen context (an all-interfaces host:port, a listen call, a host /
#      port pair) together with that product's marker or one of its routes in the same file;
#   7. a scheme-less loopback host:port on a known inference port with that port's product
#      marker and a router-side path parameter.
#
# WHAT TIES AN ALL-INTERFACES BIND TO THE SERVER (the HIGH rating):
#   * the bind is an engine bind setting (rule 2);
#   * the bind is on a known inference port and sits in a file that implements a model API
#     by rule 3, 4 or 5, or in the server binary of the product that owns the port;
#   * the bind is on 11434 and rule 6 holds;
#   * the bind is a listen call next to a route registration call (the server's own listen);
#   * the bind is on a known inference port, in a file that ties nothing by itself, and a
#     server on that same port is established elsewhere under the scan root.
# Any other all-interfaces bind is listed as untied in a file that is server evidence, and
# dropped everywhere else.
#
# WHAT IS NEVER RATED. A listen call that passes no address is stated in Evidence as that
# (for a Node listener the runtime default is every interface) and leaves the finding at
# MEDIUM: HIGH needs a written all-interfaces address. A bind in a comment is not a bind:
# whole-line and block comments are removed from configuration text before it is read, and
# a signal that sits in a trailing comment of its line is dropped.
#
# A URL to a loopback inference port (http://localhost:11434) is what a client of a
# separately installed engine contains, so on its own it is the client role.
#
# TOKEN BOUNDARIES are written as explicit ASCII classes, never \b or \w. \w matches CJK
# letters, and a UTF-8 file decoded as UTF-16 (one of the three views every PE is read in)
# is mostly CJK, so \b gives boundaries that do not exist in the file.

# Known default inference ports. Product is printed only when Marker is present in the same
# file as the port (or that product's server binary is under the scan root): a port number
# does not identify a product by itself.
$script:TcpkAiPorts = @{
    '11434' = @{ Product = 'Ollama';      Marker = 'ollama' }
    '1234'  = @{ Product = 'LM Studio';   Marker = 'lmstudio' }
    '1337'  = @{ Product = 'Jan';         Marker = 'jan' }
    '4891'  = @{ Product = 'GPT4All';     Marker = 'gpt4all' }
    '3001'  = @{ Product = 'AnythingLLM'; Marker = 'anythingllm' }
}

# Routes that only a model API serves. The remaining routes in the route regex (/v1/models,
# /api/chat, /api/tags, ...) are ordinary REST paths that unrelated products also use, so
# they count toward the two-route rule but never tie a port to a model API on their own.
$script:TcpkAiSpecificRoutes = @(
    '/v1/chat/completions', '/v1/completions', '/v1/embeddings',
    '/api/v0/chat/completions', '/api/v0/completions', '/api/v0/embeddings'
)

# Engine server executables. Each of these names is the HTTP server of its engine, so the
# file name alone places a listener component inside the target tree. Marker is the product
# the binary establishes for the scan root ('' = none of the known ports belongs to it).
# The tokens after local-ai are limited to platform, architecture, build-variant and
# version words: "local-ai-notes.exe" is somebody's note-taking application.
$script:TcpkAiServerBinaries = @(
    @{ Rx = '^ollama(?:_llama_server)?\.exe$';           Marker = 'ollama' }
    @{ Rx = '^llama-server\.exe$';                        Marker = 'llamacpp' }
    @{ Rx = '^(?:.+\.)?llamafile\.exe$';                  Marker = 'llamacpp' }
    @{ Rx = '^koboldcpp(?:[_-][a-z0-9]+){0,3}\.exe$';     Marker = 'koboldcpp' }
    @{ Rx = '^local-ai(?:[_-](?:windows|win(?:32|64)?|amd64|x64|x86[_-]64|arm64|aarch64|avx(?:2|512)?|cuda[0-9]{0,2}|cublas|vulkan|sycl|cpu|gpu|v?[0-9]+(?:\.[0-9]+){0,3})){0,5}\.exe$'; Marker = '' }
    @{ Rx = '^cortex-server\.exe$';                       Marker = 'jan' }
)

# GPU vendor math runtimes: hundreds of MB each, neither a listener nor an inference engine.
$script:TcpkAiVendorRuntimeRx = '^(?:cublas|cublaslt|cudart|cudnn|cufft|curand|cusolver|cusparse|nvrtc|nvjitlink)[0-9a-z_.\-]*\.dll$'

# How a marker key is written in Evidence.
$script:TcpkAiMarkerText = @{
    ollama = 'ollama'; lmstudio = 'lm studio'; gpt4all = 'gpt4all'; anythingllm = 'anythingllm'
    jan = 'jan'; llamacpp = 'llama.cpp'; koboldcpp = 'koboldcpp'; gguf = '.gguf model file'
}

$script:TcpkAiMarkerOrder = @('ollama', 'lmstudio', 'jan', 'gpt4all', 'anythingllm', 'koboldcpp', 'llamacpp', 'gguf')

# The engine each host variable belongs to, and that engine's server executable as a
# launcher would name it (exact-case needles: an ordinal search is a byte compare).
$script:TcpkAiEnvEngine = @{ 'OLLAMA_HOST' = 'ollama'; 'LLAMA_ARG_HOST' = 'llamacpp' }
$script:TcpkAiEngineExe = @{
    ollama   = @('ollama.exe', 'Ollama.exe', 'OLLAMA.EXE')
    llamacpp = @('llama-server.exe', 'Llama-Server.exe', 'LLAMA-SERVER.EXE')
}

# Words that may stand directly before an assignment or a command without making it a
# sentence: shell and script keywords, and the configuration keys that hold a command.
$script:TcpkAiCmdWords = @('set', 'setx', 'export', 'env', 'declare', 'const', 'let', 'var', 'return',
                           'start', 'call', 'exec', 'cmd', 'powershell', 'pwsh', 'python', 'python3', 'py', 'sudo', 'nohup')
$script:TcpkAiKeyWords = @('command', 'cmd', 'exec', 'entrypoint', 'script', 'program', 'execstart', 'env', 'environment')
# Bare words allowed between an engine executable and its flags (the key of an argument array).
$script:TcpkAiArgWords = @('args', 'arguments', 'argv', 'argumentlist', 'params', 'parameters')

# .NET members that declare an HTTP route, and those that set a process environment variable.
$script:TcpkAiMapMembers    = @('MapGet', 'MapPost', 'MapPut', 'MapDelete', 'MapPatch', 'MapMethods')
$script:TcpkAiSetterMembers = @('SetEnvironmentVariable', 'get_EnvironmentVariables', 'get_Environment', 'set_Item')

# A listen call counts as "next to" a route registration within this many characters.
$script:TcpkAiNearChars = 4000

$script:TcpkAiLineBreaks = [char[]]@([char]13, [char]10, [char]0)
$script:TcpkAiCrLf       = [char[]]@([char]13, [char]10)

$script:TcpkAiRx = $null

function Get-TcpkAiRegexSet {
    [CmdletBinding()] param()
    if ($script:TcpkAiRx) { return $script:TcpkAiRx }

    $cs = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $ic = [System.Text.RegularExpressions.RegexOptions]::CultureInvariant -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

    $nb = '(?<![A-Za-z0-9])'                 # not preceded by a letter or digit
    $hb = '(?<![A-Za-z0-9./:\-_@\[])'        # left edge of a host or URL token
    $rb = '(?<![A-Za-z0-9_.\-:%}\]/])'       # left edge of a route that is not attached to a URL
    $kp = '11434|1234|1337|4891|3001'

    # Marker boundaries. Left: no letter or digit before the name, or a camel-case hump
    # (useOllama). Right: no lower-case letter or digit after it (OllamaSharp, OLLAMA_HOST).
    # Both are case-sensitive inside a case-insensitive pattern, so "PollAmazon" and
    # "jan.aiello" stay out while an identifier that really carries the name is seen.
    $ml = '(?-i:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z]))'
    $mr = '(?-i:(?![a-z0-9]))'

    # One alternation for every product marker, as whole tokens. It is only ever applied to
    # a short window around an ordinal hit (see $script:TcpkAiMarkerNeedles), never to a
    # whole view: as a full-text sweep it cost about 90 ns per character.
    # A model publisher's organisation name is deliberately not a marker: it appears in
    # model identifiers that every product lists, so it names no product.
    $markerRx = [regex]::new($ml + '(?:(?<ollama>ollama)|(?<lmstudio>lm[ _-]?studio)|(?<gpt4all>gpt4all)|(?<anythingllm>anything[ _-]?llm)|(?<jan>jan\.ai|janhq|cortex\.cpp)|(?<llamacpp>llama[._-]?cpp|llama[-_]server|llamaedge|llamasharp)|(?<koboldcpp>koboldcpp))' + $mr, $ic)

    $modelRoute = '/v1/(?:chat/completions|completions|embeddings)|/api/v0/(?:chat/completions|completions|embeddings)'

    $script:TcpkAiRx = @{
        Markers     = $markerRx
        MarkerNames = @('ollama', 'lmstudio', 'gpt4all', 'anythingllm', 'jan', 'llamacpp', 'koboldcpp')

        # A model file reference. Case-sensitive with the dot, so four letters in compressed
        # bytes do not match. Counts as an engine marker for the route rule only.
        Gguf     = [regex]::new('\.gguf(?![A-Za-z0-9])', $cs)

        # C API symbols of the tensor / model runtime. The prefixes are the real API families;
        # a looser "llama_<anything>" would also match client frameworks named llama_*.
        Symbols  = [regex]::new('(?<![A-Za-z0-9_])(?:ggml_(?:init|free|backend_|new_tensor|graph_|type_|time_|quantize_|cpu_|vk_|cuda_|opencl_|metal_|log_|op_|get_|set_|build_|nbytes|nelements)|gguf_(?:init|free|get_|set_|find_|write_|add_)|llama_(?:model_|context_|decode|encode|tokenize|detokenize|token_|sampler_|sampling_|init_from_|load_model_|new_context_|n_ctx|n_vocab|backend_|vocab_|batch_|kv_|memory_|get_logits|get_embeddings|free|adapter_|state_|perf_|print_|log_|numa_|supports_|max_devices|time_us|chat_))[a-z0-9_]{0,48}', $cs)

        # Model API routes as whole tokens. The left edge rejects a route attached to a URL
        # (host/api/chat, ${base}/v1/models): that is a call to somebody else's server. The
        # right edge rejects a longer path (/api/chat/rooms, /api/shows, /api/generateReport).
        Routes   = [regex]::new($rb + '(?<r>/v1/(?:chat/completions|completions|embeddings|models)|/api/v0/(?:chat/completions|completions|embeddings|models)|/api/(?:generate|chat|tags|pull|push|show|embeddings|embed|ps|create|copy|delete))(?![A-Za-z0-9_/\-.%{:])', $cs)

        # Router-side path parameter under a model API path. The brace form ({id}) is not
        # accepted: generated API clients hold their paths as brace templates too.
        Patterns = [regex]::new('(?<![A-Za-z0-9_.\-:%}\]])(?<p>/(?:(?:v1/models|api/v0/models|api/blobs|api/models|v1/engines)/(?::(?:model_id|modelId|model_name|model|digest|name|id)|<arg>)|slots/:id_slot))', $cs)

        # Route registration in a syntax only a server uses, with a model API route as the
        # literal argument. '.post(' on an arbitrary receiver is NOT in here: an HTTP client
        # object is called the same way.
        RegCall  = [regex]::new('(?<![A-Za-z0-9_])(?<call>Map(?:Get|Post|Put|Methods)|HandleFunc|(?:app|router|fastify)\.(?:get|post|put|all|route)|@[A-Za-z_][A-Za-z0-9_]{0,20}\.(?:get|post|route))\s{0,3}\(\s{0,3}["''`](?<r>' + $modelRoute + ')["''`]', $cs)

        # All-interfaces host with a MANDATORY port, with or without a scheme. '+' and '*' are
        # listener prefixes only directly after '://' and directly before ':port', so a
        # wildcard domain (https://*.example.com) is not a bind.
        Wild     = [regex]::new($hb + '(?:(?<scheme>https?|wss?|tcp)://)?(?<host>0\.0\.0\.0|\[::\]|\[::0\]|(?<=://)[+*]):(?<port>[0-9]{2,5})(?![0-9])', $ic)

        # Loopback host on a known inference port, with or without a scheme.
        Loop     = [regex]::new($hb + '(?:(?<scheme>https?|wss?)://)?(?<host>localhost|127\.0\.0\.1|\[::1\]):(?<port>' + $kp + ')(?![0-9])(?<path>/[A-Za-z0-9_/\-]{1,60})?', $ic)

        # The engine's own host variable followed by an all-interfaces address (port
        # optional), anchored at the variable name. Separator forms:
        #   op    NAME=value   "NAME": "value"   ("NAME", "value")   env["NAME"] = "value"
        #   attr  key="NAME" value="..."   (an appSettings entry, a service wrapper <env>)
        #   ws    NAME value   (setx only -- see Get-TcpkAiEnvTier)
        # Spaces and tabs only between the parts: a line break is never a separator, so a
        # name and an address on two lines of extracted strings are two literals.
        EnvForm  = [regex]::new('\A(?<var>OLLAMA_HOST|LLAMA_ARG_HOST)(?:(?<q1>["''`]?)\]?[ \t]{0,4}(?<op>[=:,])[ \t]{0,4}(?<q2>["''`]?)|(?<attr>["'']\s{1,8}value\s{0,2}=\s{0,2}["''])|(?<ws>[ \t]{1,4})(?<q4>["'']?))(?:https?://)?(?<host>0\.0\.0\.0|\[::\]|\[::0\])(?::(?<port>[0-9]{2,5}))?(?![0-9.A-Za-z])', $cs)

        # A compiled .NET assembly stores env["NAME"] = "value" as two string literals with
        # a length prefix between them. In a UTF-16 view that is the name, one to three
        # characters outside printable ASCII, then the address as a whole literal.
        EnvAdjacent = [regex]::new('\A(?<var>OLLAMA_HOST|LLAMA_ARG_HOST)[^ -~]{1,3}(?<host>0\.0\.0\.0|\[::\]|\[::0\])(?::(?<port>[0-9]{2,5}))?(?![ -~])', $cs)

        # An all-interfaces address that is the value of an engine host variable: the text
        # that ends directly before it. Such an address is judged as an engine bind setting
        # (or rejected as one) and never a second time as a plain host:port.
        EnvValuePrefix = [regex]::new('(?:OLLAMA_HOST|LLAMA_ARG_HOST)(?:["''`\] \t=:,]{1,10}|["'']\s{1,8}value\s{0,2}=\s{0,2}["'']|[^ -~]{1,3})(?:https?://)?\z', $cs)

        # The engine's server on a command line: the flag with a literal value, and the
        # engine name looked up earlier on the same line.
        FlagHostVal = [regex]::new('\A--host[\s=,"'']{1,6}(?<val>localhost|\*|::|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[[0-9A-Fa-f:]{2,39}\])(?![0-9A-Za-z.])', $ic)
        FlagPortVal = [regex]::new('\A--port[\s=,"'']{1,6}(?<val>[0-9]{2,5})(?![0-9A-Za-z.])', $cs)
        FlagEngine  = [regex]::new('(?<![A-Za-z0-9_])(?<eng>llama-server|llama_server|llama-cpp-server|llama_cpp\.server|koboldcpp)(?![A-Za-z0-9_])', $ic)

        # A listen call, in the four forms a server is written with:
        #   .listen(1234, "host")     .listen(1234)     .listen(1234, () => ...)
        #   .listen({ port: 1234, host: "host" })
        #   .listen(PORT, "0.0.0.0")  a port held in a constant, with an address literal
        #   .listen(PORT)             the same with no address; the name must contain "port"
        # nohost is set only when the call visibly passes no address: it closes after the
        # port, or the next argument is a function. A second argument that is a name may be
        # an address or a callback, so nothing is said about it. The port expression may hold
        # one balanced pair of parentheses (Number(x)) and never leaves the call.
        Listen     = [regex]::new('\.listen\s{0,3}\(\s{0,3}(?:(?<port>[0-9]{2,5})(?![0-9A-Za-z_.])\s{0,3}(?:,\s{0,3}["''`](?<host>[^"''`\r\n]{1,45})["''`]|(?<nohost>\)|,\s{0,3}(?:\(|function(?![A-Za-z0-9_$])|async(?![A-Za-z0-9_$]))))?|\{(?<obj>[^{}]{0,200})\}|(?<expr>[A-Za-z_$](?:[^,"''`\r\n();{}]|\([^,"''`\r\n();{}]{0,24}\)){0,39}?)\s{0,3},\s{0,3}["''`](?<ehost>[^"''`\r\n]{1,45})["''`]|(?<bare>[A-Za-z_$][A-Za-z0-9_$.]{0,39})\s{0,3}(?:\)|,\s{0,3}(?:\(|function(?![A-Za-z0-9_$])|async(?![A-Za-z0-9_$]))))', $cs)
        ListenPort = [regex]::new('(?<![A-Za-z0-9_])port["'']?\s{0,3}:\s{0,3}(?<p>[0-9]{2,5})(?![0-9])', $ic)
        ListenHost = [regex]::new('(?<![A-Za-z0-9_])host(?:name)?["'']?\s{0,3}:\s{0,3}["''`](?<h>[^"''`\r\n]{1,45})["''`]', $ic)
        ListenHostKey = [regex]::new('(?<![A-Za-z0-9_])host(?:name)?(?![A-Za-z0-9_])', $ic)

        # host / port configuration pair with an all-interfaces host, either key order. The
        # key may carry a prefix (server.host, listen_port, serverHost).
        PairHp   = [regex]::new($nb + '["'']?(?:[A-Za-z0-9]{1,24}[_.-]?)?host(?:name)?["'']?\s{0,4}[:=]\s{0,4}["'']?(?<host>0\.0\.0\.0|\[::\])["'']?\s{0,4}[,;]?\s{0,8}["'']?(?:[A-Za-z0-9]{1,24}[_.-]?)?port["'']?\s{0,4}[:=]\s{0,4}["'']?(?<port>[0-9]{2,5})(?![0-9])', $ic)
        PairPh   = [regex]::new($nb + '["'']?(?:[A-Za-z0-9]{1,24}[_.-]?)?port["'']?\s{0,4}[:=]\s{0,4}["'']?(?<port>[0-9]{2,5})["'']?\s{0,4}[,;]?\s{0,8}["'']?(?:[A-Za-z0-9]{1,24}[_.-]?)?host(?:name)?["'']?\s{0,4}[:=]\s{0,4}["'']?(?<host>0\.0\.0\.0|\[::\])(?![0-9A-Za-z.:])', $ic)

        # A whitespace-delimited token that ends in a natural-language word: letters, with
        # optional closing punctuation. In front of the word there may be nothing, opening
        # punctuation, or a prefix that ends where a value starts ("ollama.help=Use",
        # "value=""Use", "<string>Use"): pre holds that prefix.
        # "with", "default;", "(see", "yourself:" match. "-FilePath", "{", "key=", "x.txt",
        # "OLLAMA_HOST" and a quoted JSON key do not.
        ProseTok      = [regex]::new('\A(?<pre>[^\s]*[=:>"''(\[`])?[*_]*(?<w>e\.g|i\.e|[A-Za-z][A-Za-z'']*)(?<t>[.,;:!?)\]*_]*)\z', $cs)
        # NAME=word in front of an assignment is another assignment (A=b NAME=value cmd).
        EnvAssignPre  = [regex]::new('\A[A-Z][A-Z0-9_]*=\z', $cs)
        # The engine's own command after an assignment: NAME=value ollama serve.
        EngineCmd     = [regex]::new('\A["'']?(?:\./|\.\\)?(?:ollama|llama-server|llama_server|koboldcpp)(?:\.exe)?["'']?\z', $ic)
        ProseTokRight = [regex]::new('\A[("''*_\[`]*(?:e\.g|i\.e|[A-Za-z][A-Za-z'']*)[.,;:!?)\]*_"''`]*\z', $cs)
        PlainWord     = [regex]::new('\A[A-Za-z][A-Za-z'']*(?<t>[.,:!?]*)\z', $cs)
        BatchIf       = [regex]::new('\A[ \t]*@?[ \t]*if[ \t(]', $ic)

        # Where a trailing comment starts on a line of configuration or launcher text:
        #   value  # note      value  // note      command & rem note      command & :: note
        # '//' counts only after a gap or a separator: after a colon or a path character it
        # is a URL or a path.
        TrailComment  = [regex]::new('[ \t]#|(?<![^ \t,;{}\[\]])//|&[ \t]{0,4}(?:@?rem(?=[ \t])|::)', $ic)
    }
    return $script:TcpkAiRx
}

function New-TcpkAiSignalSet {
    [CmdletBinding()] param()
    return @{
        Markers    = @{}     # product key -> $true
        Routes     = @{}     # route -> $true
        WideRoutes = @{}     # model-specific route that is a whole UTF-16 string literal -> $true (PE only)
        Patterns   = @{}     # router-side path parameter -> $true
        RegCalls   = @{}     # route registration call -> $true
        Binds      = @{}     # normalized text -> record (all-interfaces forms, engine forms, listen calls)
        Loops      = @{}     # normalized text -> record (loopback host on a known inference port)
        Symbols    = @{}     # engine C API symbol -> $true (PE only)
        Hints      = @{}     # 'map:<member>', 'member:<member>', 'exe:<engine>' -> $true (PE only)
        Errors     = 0
    }
}

# Record one bind. A form seen twice keeps the stronger tier and stays "near" once it was.
# HostForm (listen calls only): 'literal' an address literal, 'none' no address argument,
# 'expr' an address that is not a literal or an argument that cannot be told apart.
function Add-TcpkAiBind {
    param([hashtable]$Acc, [string]$Kind, [string]$BindHost, [string]$Port, [bool]$Wild, [string]$Show,
          [string]$Tier = '', [string]$Var = '', [bool]$Near = $false, [string]$HostForm = '')
    if (-not $Show) { return }
    if ($Acc.Binds.ContainsKey($Show)) {
        $old = $Acc.Binds[$Show]
        if ($Near) { $old.Near = $true }
        $rank = @{ '' = 0; 'literal' = 1; 'root' = 2; 'adjacent' = 3; 'solid' = 4 }
        if ($rank["$Tier"] -gt $rank["$($old.Tier)"]) { $old.Tier = $Tier }
        return
    }
    if ($Acc.Binds.Count -ge 60) { return }
    $hp = ''
    if ($BindHost -and $Port) { $hp = "${BindHost}:$Port" }
    $Acc.Binds[$Show] = [pscustomobject]@{ Kind = $Kind; BindHost = $BindHost; Port = $Port; Wild = $Wild; HostPort = $hp; Show = $Show; Tier = $Tier; Var = $Var; Near = $Near; HostForm = $HostForm }
}

# Is this literal an all-interfaces address?
function Test-TcpkAiWildHost {
    param([string]$Value)
    return (@('0.0.0.0', '::', '[::]', '[::0]', '*', '+') -contains "$Value".Trim())
}

# Apply $Rx to a small window around every ordinal occurrence of $Needle and return, per
# occurrence, the first match that covers the needle. When $PosList is given it receives the
# position of each returned match in $Text, in the same order.
#
# WHY NOT RUN THE REGEX OVER THE WHOLE VIEW. A PE below the streaming threshold is read as
# three verbatim views of up to 16 M characters each, and a bundled script can be 20 MB on
# one line. A dozen patterns that open with a lookbehind or an alternation walk every
# character of every view in the regex interpreter. An ordinal IndexOf is a native byte
# compare, the needles below are rare in ordinary binaries, and the regex then only ever sees
# a few dozen characters. Measured on a 34 MB string view: 3.4 s before, 0.3 s after.
#
# A match is accepted only if it covers the needle. Anything else the pattern finds inside
# the window either has its own needle (and is seen from there) or starts on the cut edge,
# where its left boundary could not be tested.
function Find-TcpkAiMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Needle,
        [Parameter(Mandatory)][regex]$Rx,
        [int]$Before = 1,
        [int]$After = 32,
        [int]$MaxHits = 5000,
        [System.Collections.Generic.List[int]]$PosList = $null
    )
    $out  = New-Object 'System.Collections.Generic.List[object]'
    $ord  = [System.StringComparison]::Ordinal
    $n    = $Text.Length
    $i    = 0
    $hits = 0
    while ($i -lt $n) {
        $i = $Text.IndexOf($Needle, $i, $ord)
        if ($i -lt 0) { break }
        $hits++
        $s = $i - $Before
        if ($s -lt 0) { $s = 0 }
        $e = $i + $Needle.Length + $After
        if ($e -gt $n) { $e = $n }
        $rel = $i - $s
        $win = $Text.Substring($s, $e - $s)
        foreach ($m in $Rx.Matches($win)) {
            if ($m.Index -gt $rel) { break }
            if (($m.Index + $m.Length) -lt ($rel + $Needle.Length)) { continue }
            if ($Before -gt 0 -and $s -gt 0 -and $m.Index -eq 0) { continue }
            $out.Add($m)
            if ($null -ne $PosList) { $PosList.Add($s + $m.Index) }
            break
        }
        $i += $Needle.Length
        if ($hits -ge $MaxHits) { break }
    }
    return $out.ToArray()
}

# Does $Needle occur in $Text as a whole identifier (no letter, digit or underscore on
# either side)? Ordinal search, no regex.
function Test-TcpkAiWholeToken {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Needle, [int]$MaxHits = 2000)
    $ord  = [System.StringComparison]::Ordinal
    $n    = $Text.Length
    $i    = 0
    $hits = 0
    while ($i -lt $n) {
        $i = $Text.IndexOf($Needle, $i, $ord)
        if ($i -lt 0) { return $false }
        $hits++
        $ok = $true
        if ($i -gt 0) {
            $c = $Text[$i - 1]
            if (($c -ge 'a' -and $c -le 'z') -or ($c -ge 'A' -and $c -le 'Z') -or ($c -ge '0' -and $c -le '9') -or $c -eq '_') { $ok = $false }
        }
        $e = $i + $Needle.Length
        if ($ok -and $e -lt $n) {
            $c = $Text[$e]
            if (($c -ge 'a' -and $c -le 'z') -or ($c -ge 'A' -and $c -le 'Z') -or ($c -ge '0' -and $c -le '9') -or $c -eq '_') { $ok = $false }
        }
        if ($ok) { return $true }
        $i = $e
        if ($hits -ge $MaxHits) { break }
    }
    return $false
}

# Is this character outside printable ASCII? In a binary view that is where one string
# literal ends and the next begins (a NUL, a length prefix, a line break of the extractor).
function Test-TcpkAiEdgeChar {
    param([char]$Char)
    $v = [int]$Char
    return ($v -lt 32 -or $v -gt 126)
}

function Test-TcpkAiHasNonAscii {
    param([string]$Value)
    foreach ($ch in $Value.ToCharArray()) { if ([int]$ch -gt 126) { return $true } }
    return $false
}

# The whitespace-delimited token that ends before $Pos on the same line.
#   Kind 'start'     nothing before it on the line, or a literal edge of a binary view
#   Kind 'attached'  a character other than a space sits directly before $Pos
#   Kind 'token'     Token / Start describe the word before the gap
function Get-TcpkAiLeftToken {
    param([Parameter(Mandatory)][string]$Text, [int]$Pos)
    if ($Pos -le 0) { return @{ Kind = 'start'; Token = ''; Start = 0 } }
    $c = $Text[$Pos - 1]
    if ($c -ne ' ' -and $c -ne "`t") {
        if (Test-TcpkAiEdgeChar $c) { return @{ Kind = 'start'; Token = ''; Start = $Pos } }
        return @{ Kind = 'attached'; Token = ''; Start = $Pos }
    }
    $j = $Pos - 1
    while ($j -ge 0 -and ($Text[$j] -eq ' ' -or $Text[$j] -eq "`t") -and ($Pos - $j) -le 80) { $j-- }
    if ($j -lt 0) { return @{ Kind = 'start'; Token = ''; Start = 0 } }
    if ([int]$Text[$j] -lt 32) { return @{ Kind = 'start'; Token = ''; Start = $j + 1 } }
    $k = $j
    while ($k -ge 0 -and ($j - $k) -lt 48) {
        $d = $Text[$k]
        if ($d -eq ' ' -or [int]$d -lt 32) { break }
        $k--
    }
    return @{ Kind = 'token'; Token = $Text.Substring($k + 1, $j - $k); Start = $k + 1 }
}

# Is the text that ends at $Pos a sentence leading into what starts there?
#
# $Pos is the first character of an assignment (the variable name) or of a command (the
# executable). Opening quotes and brackets directly before it are skipped. The token before
# that decides: a natural-language word means the form is quoted inside a sentence ("start
# it with NAME=...", "Run <command>"). A shell or script keyword (set, call, const, ...) or
# a configuration key that holds a command (command:) is looked through, and the token in
# front of the keyword is then judged the same way ("Docker, set NAME=..." is a sentence).
function Test-TcpkAiProseLeft {
    param([Parameter(Mandatory)][string]$Text, [int]$Pos)
    $rx = Get-TcpkAiRegexSet
    $i = $Pos
    $skipped = 0
    while ($i -gt 0 -and $skipped -lt 4 -and '"''`([{'.IndexOf($Text[$i - 1]) -ge 0) { $i--; $skipped++ }
    $afterSet = $false
    for ($hop = 0; $hop -lt 3; $hop++) {
        $lt = Get-TcpkAiLeftToken -Text $Text -Pos $i
        if ($lt.Kind -ne 'token') { return $false }
        $tok = "$($lt.Token)"
        $prose = $false
        $keyword = $false
        if (Test-TcpkAiHasNonAscii $tok) { $prose = $true }
        else {
            $m = $rx.ProseTok.Match($tok)
            if ($m.Success -and -not $rx.EnvAssignPre.IsMatch($m.Groups['pre'].Value)) {
                $w = $m.Groups['w'].Value.ToLowerInvariant()
                $t = $m.Groups['t'].Value
                if (($t -eq '' -and $script:TcpkAiCmdWords -contains $w) -or ($t -eq ':' -and $script:TcpkAiKeyWords -contains $w)) {
                    $keyword = $true
                    if ($w -eq 'set' -or $w -eq 'setx') { $afterSet = $true }
                } else { $prose = $true }
            }
        }
        if ($prose) {
            # "if defined EXPOSE set NAME=value": the word before the keyword belongs to a
            # batch condition, not to a sentence.
            if ($afterSet -and $hop -gt 0) {
                $ls = $Text.LastIndexOfAny($script:TcpkAiLineBreaks, $lt.Start)
                $from = $ls + 1
                if (($lt.Start - $from) -le 200 -and $rx.BatchIf.IsMatch($Text.Substring($from, $lt.Start - $from))) { return $false }
            }
            return $true
        }
        if (-not $keyword) { return $false }
        $i = [int]$lt.Start
    }
    return $false
}

# Does a sentence continue after position $End (the end of an assigned value)?
# Closing quotes and brackets are skipped. A comma or semicolon after a quoted value is
# code. Otherwise a gap followed by a natural-language word is a sentence ("... and
# restart", "... so it accepts remote connections"). A switch (/M), an operator (&&), an
# attribute (extra="x") and a comment marker are not words.
function Test-TcpkAiProseRight {
    param([Parameter(Mandatory)][string]$Text, [int]$End, [bool]$Quoted = $false)
    $rx = Get-TcpkAiRegexSet
    $n = $Text.Length
    $i = $End
    $closedQuote = $false
    $k = 0
    while ($i -lt $n -and $k -lt 4 -and '"''`)]}'.IndexOf($Text[$i]) -ge 0) {
        if ('"''`'.IndexOf($Text[$i]) -ge 0) { $closedQuote = $true }
        $i++; $k++
    }
    if ($i -ge $n) { return $false }
    $c = $Text[$i]
    if ($c -eq ',' -or $c -eq ';') {
        if ($Quoted -and $closedQuote) { return $false }
        $i++
        if ($i -ge $n) { return $false }
        $c = $Text[$i]
    }
    if ($c -ne ' ' -and $c -ne "`t") { return $false }
    while ($i -lt $n -and ($Text[$i] -eq ' ' -or $Text[$i] -eq "`t")) { $i++ }
    if ($i -ge $n) { return $false }
    if ([int]$Text[$i] -lt 32) { return $false }
    $j = $i
    while ($j -lt $n -and ($j - $i) -lt 48) {
        $d = $Text[$j]
        if ($d -eq ' ' -or [int]$d -lt 32) { break }
        $j++
    }
    $tok = $Text.Substring($i, $j - $i)
    if (Test-TcpkAiHasNonAscii $tok) { return $true }
    if ($rx.EngineCmd.IsMatch($tok)) { return $false }
    return $rx.ProseTokRight.IsMatch($tok)
}

# Does $S read as command-line material: switches, their values, quotes and separators?
#
# Used on the text between an engine executable and its host / port flag (-Whole: all of
# it must be arguments, and a command separator in between means the flag belongs to
# another command) and on the text after the flag's value (until the command ends).
# A sentence gives itself away by a bare word where no value is expected: "llama-server is
# started with --host", "--port 8080 and paste the address", "--port 8080, then enter".
function Test-TcpkAiArgRun {
    param([AllowNull()][AllowEmptyString()][string]$S, [switch]$Whole)
    if ([string]::IsNullOrEmpty($S)) { return $true }
    $rx = Get-TcpkAiRegexSet
    $n = $S.Length
    $i = 0
    $expectValue = $false
    $guard = 0
    while ($i -lt $n) {
        $guard++
        if ($guard -gt 400) { break }
        $c = $S[$i]
        $code = [int]$c
        if ($code -eq 13 -or $code -eq 10 -or $code -eq 0) { return $true }
        if ($code -le 32 -or $code -gt 126) { $i++; continue }      # a gap, or a literal edge in a binary view
        if ('"''`,[]()'.IndexOf($c) -ge 0) { $i++; continue }
        if ('&|;<>{}#'.IndexOf($c) -ge 0) { return (-not $Whole) }
        $j = $i
        while ($j -lt $n) {
            $d = $S[$j]
            $dc = [int]$d
            if ($dc -le 32 -or $dc -gt 126 -or '"''`,[]()'.IndexOf($d) -ge 0) { break }
            $j++
        }
        $tok = $S.Substring($i, $j - $i)
        if ($tok.Length -ge 2 -and $tok[0] -eq '-' -and ($tok[1] -eq '-' -or [char]::IsLetter($tok[1]))) {
            $expectValue = ($tok.IndexOf('=') -lt 0)
            $i = $j
            continue
        }
        if ($expectValue) { $expectValue = $false; $i = $j; continue }
        $pm = $rx.PlainWord.Match($tok)
        if ($pm.Success) {
            if ($Whole) {
                $bare = $tok.Substring(0, $tok.Length - $pm.Groups['t'].Length).ToLowerInvariant()
                if ($script:TcpkAiArgWords -notcontains $bare) { return $false }
            } else {
                $tail = $pm.Groups['t'].Value
                if ($tail.IndexOf('.') -ge 0 -or $tail.IndexOf('!') -ge 0 -or $tail.IndexOf('?') -ge 0) { return $false }
                $k = $j
                $gap = $false
                while ($k -lt $n -and ($S[$k] -eq ' ' -or $S[$k] -eq "`t")) { $k++; $gap = $true }
                if ($gap -and $k -lt $n -and [char]::IsLetter($S[$k])) { return $false }
            }
        }
        $i = $j
    }
    return $true
}

# Does position $Pos sit in a trailing comment of its line? For configuration and launcher
# text only. Whole-line and block comments are removed before the text is analysed (see
# Get-TcpkAiConfigText); this covers the comment that follows active text on the same line:
#   OLLAMA_HOST=127.0.0.1   # OLLAMA_HOST=0.0.0.0 to expose
# A marker counts only when the quotes before it on the line are balanced, so a '#' or a
# '//' inside a string value ("#fff", "http://host") is not read as one.
function Test-TcpkAiTrailingComment {
    param([Parameter(Mandatory)][string]$Text, [int]$Pos)
    if ($Pos -le 1 -or $Pos -gt $Text.Length) { return $false }
    $from = $Text.LastIndexOfAny($script:TcpkAiLineBreaks, $Pos - 1) + 1
    $len = $Pos - $from
    if ($len -lt 2 -or $len -gt 600) { return $false }
    $line = $Text.Substring($from, $len)
    $rx = Get-TcpkAiRegexSet
    foreach ($m in $rx.TrailComment.Matches($line)) {
        $dq = 0
        $sq = 0
        for ($i = 0; $i -lt $m.Index; $i++) {
            $c = $line[$i]
            if ($c -eq '"') { $dq++ } elseif ($c -eq "'") { $sq++ }
        }
        if (($dq % 2) -eq 0 -and ($sq % 2) -eq 0) { return $true }
    }
    return $false
}

# How much an engine host variable assignment proves, by the kind of file it is in.
#   'solid'     a structured setting: an assignment line of a launcher or configuration
#               file, or a key with a separately quoted value in a script or JSON file
#   'literal'   NAME=value as one whole string literal. A process environment block has
#               this shape, and so does a copyable snippet in a help screen, so it is
#               shown in Evidence and never rated
#   'root'      a form that is not a setting by its own shape
#   'adjacent'  name and value as two string literals of a compiled assembly: resolved in
#               Resolve-TcpkAiFileRole (needs an environment setter member in the file)
#   ''          not a setting (a sentence, or a form this file type does not use)
#
# line  (.bat .cmd .ps1 .env .ini .yaml ...): any separator form that is not part of a
#       sentence. The bare "NAME value" form only directly after setx.
# xml   (.config .xml): the same, including the key="NAME" value="..." attribute pair.
# js / json: only a form with structure -- a separately quoted value (NAME: "value",
#       env["NAME"] = "value", ("NAME", "value")) or a string literal that is exactly
#       "NAME=value". "set NAME=value" inside a string is documentation.
# pe:   a literal that is exactly NAME=value (what a process environment block or putenv
#       takes) is solid. Any other form outside a sentence needs the engine binary.
function Get-TcpkAiEnvTier {
    param([Parameter(Mandatory)][string]$Text, [int]$Pos, [Parameter(Mandatory)]$Match, [string]$Style)
    $n    = $Text.Length
    $end  = $Pos + $Match.Length
    $op   = $Match.Groups['op'].Value
    $isAttr = $Match.Groups['attr'].Success
    $isWs   = $Match.Groups['ws'].Success
    $q1 = $Match.Groups['q1'].Value
    $q2 = $Match.Groups['q2'].Value
    $quotedVal = ([bool]$q2 -or $isAttr -or [bool]$Match.Groups['q4'].Value)
    $prev = [char]0
    if ($Pos -gt 0) { $prev = $Text[$Pos - 1] }
    $next = [char]0
    if ($end -lt $n) { $next = $Text[$end] }

    if ($Style -eq 'pe') {
        if ($isWs) { return '' }
        if ($op -eq '=' -and -not $q1 -and -not $q2 -and (Test-TcpkAiEdgeChar $prev) -and (Test-TcpkAiEdgeChar $next)) { return 'literal' }
        if (Test-TcpkAiProseLeft -Text $Text -Pos $Pos) { return '' }
        if (Test-TcpkAiProseRight -Text $Text -End $end -Quoted $quotedVal) { return '' }
        return 'root'
    }

    if ($Style -ne 'js' -and (Test-TcpkAiTrailingComment -Text $Text -Pos $Pos)) { return '' }

    if ($Style -eq 'js' -or $Style -eq 'json') {
        if ($isWs -or $isAttr) { return '' }
        $structured = $false
        $wholeLiteral = $false
        if ($q2) { $structured = $true }
        elseif ($op -eq '=' -and -not $q1 -and '"''`'.IndexOf($prev) -ge 0 -and $next -eq $prev) { $structured = $true; $wholeLiteral = $true }
        if (-not $structured) { return '' }
        if (Test-TcpkAiProseLeft -Text $Text -Pos $Pos) { return '' }
        if (Test-TcpkAiProseRight -Text $Text -End $end -Quoted $quotedVal) { return '' }
        if ($wholeLiteral) { return 'literal' }
        return 'solid'
    }

    # line / xml
    if ($isWs) {
        $lt = Get-TcpkAiLeftToken -Text $Text -Pos $Pos
        if ($lt.Kind -ne 'token' -or "$($lt.Token)".TrimStart('@').ToLowerInvariant() -ne 'setx') { return '' }
    }
    if (Test-TcpkAiProseLeft -Text $Text -Pos $Pos) { return '' }
    if (Test-TcpkAiProseRight -Text $Text -End $end -Quoted $quotedVal) { return '' }
    # NAME=value as one whole quoted string that is the value of some OTHER key (a locale
    # entry, a snippet variable: help.step2: "OLLAMA_HOST=0.0.0.0") is text. The same
    # literal after an environment key, or after set / export / a list dash, is a setting.
    if ($op -eq '=' -and -not $q1 -and -not $q2 -and $Pos -gt 1 -and '"'''.IndexOf($prev) -ge 0 -and $next -eq $prev) {
        $quoteAt = $Pos - 1
        $lineStart = $Text.LastIndexOfAny($script:TcpkAiLineBreaks, $quoteAt - 1) + 1
        $left = $Text.Substring($lineStart, $quoteAt - $lineStart).TrimEnd()
        if ($left.Length -gt 0 -and ($left.EndsWith(':') -or $left.EndsWith('='))) {
            $km = [regex]::Match($left, '([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\z')
            $key = ''
            if ($km.Success) { $key = $km.Groups[1].Value.ToLowerInvariant() }
            if ($key -notmatch '^(?:env|environment|environmentvariables?|setenv|appenvironment(?:extra)?|variables?)$') { return 'literal' }
        }
    }
    return 'solid'
}

# The engine's host variable assigned an all-interfaces address. Every occurrence of the
# variable name is looked at on its own.
function Add-TcpkAiEnvBinds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][hashtable]$Acc, [string]$Style = 'pe', [switch]$Wide)
    $rx  = Get-TcpkAiRegexSet
    $ord = [System.StringComparison]::Ordinal
    $n   = $Text.Length
    foreach ($needle in @('OLLAMA_HOST', 'LLAMA_ARG_HOST')) {
        $i = 0
        $hits = 0
        while ($i -lt $n) {
            $i = $Text.IndexOf($needle, $i, $ord)
            if ($i -lt 0) { break }
            $hits++
            $ok = $true
            if ($i -gt 0) {
                $c = $Text[$i - 1]
                if (($c -ge 'a' -and $c -le 'z') -or ($c -ge 'A' -and $c -le 'Z') -or ($c -ge '0' -and $c -le '9') -or $c -eq '_') { $ok = $false }
            }
            if ($ok) {
                $len = 96
                if (($i + $len) -gt $n) { $len = $n - $i }
                $tail = $Text.Substring($i, $len)
                $m = $rx.EnvForm.Match($tail)
                $tier = ''
                if ($m.Success) {
                    $tier = Get-TcpkAiEnvTier -Text $Text -Pos $i -Match $m -Style $Style
                } elseif ($Wide -and $Style -eq 'pe') {
                    $m = $rx.EnvAdjacent.Match($tail)
                    if ($m.Success -and ($i -eq 0 -or (Test-TcpkAiEdgeChar $Text[$i - 1]))) { $tier = 'adjacent' }
                }
                if ($tier) {
                    $h = $m.Groups['host'].Value
                    $p = ''
                    if ($m.Groups['port'].Success) { $p = $m.Groups['port'].Value }
                    $show = $m.Groups['var'].Value + '=' + $h
                    if ($p) { $show += ":$p" }
                    Add-TcpkAiBind -Acc $Acc -Kind 'env' -BindHost $h -Port $p -Wild $true -Show $show -Tier $tier -Var $m.Groups['var'].Value
                }
            }
            $i += $needle.Length
            if ($hits -ge 2000) { break }
        }
    }
}

# The engine's server on a command line with its host or port flag:
#   llama-server.exe --host 0.0.0.0 --port 8080      ["llama-server", "--host", "0.0.0.0"]
# Every flag occurrence is looked at on its own. The value must be an address or a number
# (help text such as "--host HOST" is not a bind), the engine name must sit earlier on the
# same line within 240 characters, and the whole run from the executable to the end of the
# command must read as a command line and not as a sentence that quotes one.
function Add-TcpkAiFlagBinds {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][hashtable]$Acc, [string]$Style = 'pe')
    $rx  = Get-TcpkAiRegexSet
    $ord = [System.StringComparison]::Ordinal
    $n   = $Text.Length
    $isConfig = ($Style -eq 'json' -or $Style -eq 'xml' -or $Style -eq 'line')
    foreach ($flag in @('--host', '--port')) {
        $valRx = $rx.FlagPortVal
        if ($flag -eq '--host') { $valRx = $rx.FlagHostVal }
        $i = 0
        $hits = 0
        while ($i -lt $n) {
            $i = $Text.IndexOf($flag, $i, $ord)
            if ($i -lt 0) { break }
            $hits++
            $len = 64
            if (($i + $len) -gt $n) { $len = $n - $i }
            $vm = $valRx.Match($Text.Substring($i, $len))
            if ($vm.Success) {
                $s = $i - 240
                if ($s -lt 0) { $s = 0 }
                $before = $Text.Substring($s, $i - $s)
                $cut = $before.LastIndexOfAny($script:TcpkAiLineBreaks)
                if ($cut -ge 0) { $before = $before.Substring($cut + 1) }
                $lineStart = $i - $before.Length
                $em = $null
                foreach ($x in $rx.FlagEngine.Matches($before)) { $em = $x }
                if ($em) {
                    $eng      = $em.Groups['eng'].Value.ToLowerInvariant()
                    $engStart = $lineStart + $em.Index
                    $engEnd   = $engStart + $em.Length
                    $middle   = $Text.Substring($engEnd, $i - $engEnd)
                    if ($middle.Length -ge 4 -and $middle.Substring(0, 4).ToLowerInvariant() -eq '.exe') { $middle = $middle.Substring(4) }
                    # The executable token: the engine name with the path in front of it.
                    $exeStart = $engStart
                    while ($exeStart -gt $lineStart -and ($engStart - $exeStart) -lt 160) {
                        $pc = $Text[$exeStart - 1]
                        if (($pc -ge 'a' -and $pc -le 'z') -or ($pc -ge 'A' -and $pc -le 'Z') -or ($pc -ge '0' -and $pc -le '9') -or '_.\/:%~$-{}'.IndexOf($pc) -ge 0) { $exeStart-- } else { break }
                    }
                    $valEnd = $i + $vm.Length
                    $rlen = 200
                    if (($valEnd + $rlen) -gt $n) { $rlen = $n - $valEnd }
                    $right = $Text.Substring($valEnd, $rlen)
                    if ((Test-TcpkAiArgRun -S $middle -Whole) -and
                        (-not (Test-TcpkAiProseLeft -Text $Text -Pos $exeStart)) -and
                        (Test-TcpkAiArgRun -S $right) -and
                        (-not ($isConfig -and (Test-TcpkAiTrailingComment -Text $Text -Pos $exeStart)))) {
                        $v = $vm.Groups['val'].Value
                        # Which engine's server binary this command line starts.
                        $engKey = 'llamacpp'
                        if ($eng -eq 'koboldcpp') { $engKey = 'koboldcpp' }
                        # A command line in a launcher or configuration file is a setting.
                        # In a script bundle, a JSON file or a compiled file the flag counts
                        # as structured only when it is its own quoted token (an argument
                        # array: "--host", "0.0.0.0"). The same command inside one string
                        # literal is what a help screen prints, so it is 'literal'.
                        $flagTier = 'solid'
                        if ($Style -eq 'pe') { $flagTier = 'literal' }
                        elseif ($Style -eq 'js' -or $Style -eq 'json') {
                            $own = $false
                            $after = $i + $flag.Length
                            if ($i -gt 0 -and $after -lt $n) {
                                $qc = $Text[$i - 1]
                                if ('"''`'.IndexOf($qc) -ge 0 -and $Text[$after] -eq $qc) { $own = $true }
                            }
                            if (-not $own) {
                                $flagTier = 'literal'
                                # One command string handed straight to a process-start
                                # call (exec("llama-server --host ...")) is a launch.
                                if ($Style -eq 'js' -and $exeStart -gt 0 -and '"''`'.IndexOf($Text[$exeStart - 1]) -ge 0) {
                                    $cs = $exeStart - 1 - 28
                                    if ($cs -lt 0) { $cs = 0 }
                                    $callLeft = $Text.Substring($cs, ($exeStart - 1) - $cs)
                                    if ([regex]::IsMatch($callLeft, '(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\)?\s*\(\s*\z')) { $flagTier = 'solid' }
                                }
                            }
                        }
                        if ($flag -eq '--host') {
                            Add-TcpkAiBind -Acc $Acc -Kind 'flag' -BindHost $v -Port '' -Wild (Test-TcpkAiWildHost $v) -Show "$eng --host $v" -Tier $flagTier -Var $engKey
                        } else {
                            Add-TcpkAiBind -Acc $Acc -Kind 'flag' -BindHost '' -Port $v -Wild $false -Show "$eng --port $v" -Tier $flagTier -Var $engKey
                        }
                    }
                }
            }
            $i += $flag.Length
            if ($hits -ge 5000) { break }
        }
    }
}

# Collect every signal except product markers from one decoded view (or one chunk of a
# large file). Markers are added separately by Add-TcpkAiMarkers, and only for a file that
# produced something a marker could give context to.
#   -Style  'pe' | 'js' | 'json' | 'xml' | 'line': decides which assignment forms count
#   -Wide   the view is a UTF-16 decode of a PE (where .NET string literals live)
function Add-TcpkAiSignals {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][hashtable]$Acc,
        [switch]$Symbols,
        [string]$Style = 'pe',
        [switch]$Wide
    )
    if ([string]::IsNullOrEmpty($Text)) { return }
    $rx  = Get-TcpkAiRegexSet
    $ord = [System.StringComparison]::Ordinal
    $n   = $Text.Length
    $isConfig = ($Style -eq 'json' -or $Style -eq 'xml' -or $Style -eq 'line')

    # --- model API routes, router-side path parameters, registration calls ---
    # First, because a listen call is judged by its distance to a registration call.
    $regPos = New-Object 'System.Collections.Generic.List[int]'
    $anyRoute = $false
    foreach ($needle in @('/v1/', '/api/')) {
        if ($Text.IndexOf($needle, $ord) -lt 0) { continue }
        $anyRoute = $true
        try {
            $pos = New-Object 'System.Collections.Generic.List[int]'
            $found = @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.Routes -Before 1 -After 26 -MaxHits 20000 -PosList $pos)
            for ($k = 0; $k -lt $found.Count; $k++) {
                $r = $found[$k].Groups['r'].Value
                $Acc.Routes[$r] = $true
                # A model-specific route that is a whole string literal of a UTF-16 view.
                if ($Wide -and ($script:TcpkAiSpecificRoutes -contains $r)) {
                    $a = $pos[$k]
                    $b = $a + $found[$k].Length
                    $left  = ($a -eq 0) -or (Test-TcpkAiEdgeChar $Text[$a - 1])
                    $right = ($b -ge $n) -or (Test-TcpkAiEdgeChar $Text[$b])
                    if ($left -and $right) { $Acc.WideRoutes[$r] = $true }
                }
            }
        } catch { $Acc.Errors++ }
    }
    if ($anyRoute) {
        foreach ($needle in @('/:', '/<arg>')) {
            if ($Acc.Patterns.Count -ge 8) { break }
            try {
                foreach ($m in @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.Patterns -Before 20 -After 24 -MaxHits 20000)) {
                    if ($Acc.Patterns.Count -ge 8) { break }
                    $Acc.Patterns[$m.Groups['p'].Value] = $true
                }
            } catch { $Acc.Errors++ }
        }
        foreach ($needle in @('/v1/chat/completions', '/v1/completions', '/v1/embeddings', '/api/v0/')) {
            try {
                $pos = New-Object 'System.Collections.Generic.List[int]'
                $found = @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.RegCall -Before 48 -After 28 -MaxHits 2000 -PosList $pos)
                for ($k = 0; $k -lt $found.Count; $k++) {
                    if ($regPos.Count -lt 400) { $regPos.Add($pos[$k]) }
                    if ($Acc.RegCalls.Count -lt 8) { $Acc.RegCalls[($found[$k].Groups['call'].Value + '("' + $found[$k].Groups['r'].Value + '")')] = $true }
                }
            } catch { $Acc.Errors++ }
        }
    }

    # --- all-interfaces binds: URL, scheme-less host:port, host / port pair ---
    $anyWild = $false
    foreach ($needle in @('0.0.0.0', '[::', '://+:', '://*:')) {
        if ($Text.IndexOf($needle, $ord) -lt 0) { continue }
        $anyWild = $true
        try {
            $pos = New-Object 'System.Collections.Generic.List[int]'
            $found = @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.Wild -Before 12 -After 12 -MaxHits 2000 -PosList $pos)
            for ($k = 0; $k -lt $found.Count; $k++) {
                $m = $found[$k]
                $a = $pos[$k]
                # The value of an engine host variable is judged as that, below.
                $ps = $a - 48
                if ($ps -lt 0) { $ps = 0 }
                if ($a -gt $ps -and $rx.EnvValuePrefix.IsMatch($Text.Substring($ps, $a - $ps))) { continue }
                # An address in the middle of a sentence ("... listens on 0.0.0.0:11434
                # when ...") is documentation, not a bind. Neither is one in a trailing
                # comment of a configuration line.
                if ((Test-TcpkAiProseLeft -Text $Text -Pos $a) -and (Test-TcpkAiProseRight -Text $Text -End ($a + $m.Length))) { continue }
                if ($isConfig -and (Test-TcpkAiTrailingComment -Text $Text -Pos $a)) { continue }
                $h = $m.Groups['host'].Value
                $p = $m.Groups['port'].Value
                if ($m.Groups['scheme'].Success) {
                    Add-TcpkAiBind -Acc $Acc -Kind 'url' -BindHost $h -Port $p -Wild $true -Show ($m.Groups['scheme'].Value.ToLowerInvariant() + "://${h}:$p")
                } else {
                    Add-TcpkAiBind -Acc $Acc -Kind 'hostport' -BindHost $h -Port $p -Wild $true -Show "${h}:$p"
                }
            }
        } catch { $Acc.Errors++ }
        if ($needle -ne '0.0.0.0' -and $needle -ne '[::') { continue }
        try {
            foreach ($pairRx in @($rx.PairHp, $rx.PairPh)) {
                $pos = New-Object 'System.Collections.Generic.List[int]'
                $found = @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $pairRx -Before 110 -After 110 -MaxHits 2000 -PosList $pos)
                for ($k = 0; $k -lt $found.Count; $k++) {
                    $m = $found[$k]
                    # The engine's own host variable is reported in its own form below; as a
                    # generic pair it would show up a second time, and as an untied bind.
                    if ($m.Value.IndexOf('OLLAMA_HOST', $ord) -ge 0 -or $m.Value.IndexOf('LLAMA_ARG_HOST', $ord) -ge 0) { continue }
                    if ($isConfig -and (Test-TcpkAiTrailingComment -Text $Text -Pos $pos[$k])) { continue }
                    $h = $m.Groups['host'].Value
                    $p = $m.Groups['port'].Value
                    Add-TcpkAiBind -Acc $Acc -Kind 'pair' -BindHost $h -Port $p -Wild $true -Show "host=$h port=$p"
                }
            }
        } catch { $Acc.Errors++ }
    }

    # --- engine host variable assigned an all-interfaces address ---
    if ($anyWild -and ($Text.IndexOf('OLLAMA_HOST', $ord) -ge 0 -or $Text.IndexOf('LLAMA_ARG_HOST', $ord) -ge 0)) {
        try { Add-TcpkAiEnvBinds -Text $Text -Acc $Acc -Style $Style -Wide:$Wide } catch { $Acc.Errors++ }
    }

    # --- engine server command line with its host / port flag ---
    $hasLlama = ($Text.IndexOf('llama', $ord) -ge 0)
    if ($hasLlama -or ($Text.IndexOf('kobold', $ord) -ge 0)) {
        try { Add-TcpkAiFlagBinds -Text $Text -Acc $Acc -Style $Style } catch { $Acc.Errors++ }
    }

    # --- listen call ---
    try {
        $pos = New-Object 'System.Collections.Generic.List[int]'
        $found = @(Find-TcpkAiMatches -Text $Text -Needle '.listen' -Rx $rx.Listen -Before 0 -After 260 -MaxHits 5000 -PosList $pos)
        for ($k = 0; $k -lt $found.Count; $k++) {
            $m = $found[$k]
            $p = ''
            $h = ''
            $first = ''
            $hostForm = 'expr'
            $near = $false
            foreach ($rp in $regPos) { if ([Math]::Abs($rp - $pos[$k]) -le $script:TcpkAiNearChars) { $near = $true; break } }
            if ($m.Groups['port'].Success) {
                $p = $m.Groups['port'].Value
                $first = $p
                if ($m.Groups['host'].Success) { $h = $m.Groups['host'].Value; $hostForm = 'literal' }
                elseif ($m.Groups['nohost'].Success) { $hostForm = 'none' }
            } elseif ($m.Groups['obj'].Success) {
                $obj = $m.Groups['obj'].Value
                $pm = $rx.ListenPort.Match($obj)
                if (-not $pm.Success) { continue }
                $p = $pm.Groups['p'].Value
                $first = $p
                $hm = $rx.ListenHost.Match($obj)
                if ($hm.Success) { $h = $hm.Groups['h'].Value; $hostForm = 'literal' }
                elseif (-not $rx.ListenHostKey.IsMatch($obj)) { $hostForm = 'none' }
            } elseif ($m.Groups['expr'].Success) {
                # The port is not a literal. Only an all-interfaces address literal is of
                # interest here; the expression is printed only when it is a plain name.
                $h = $m.Groups['ehost'].Value
                if (-not (Test-TcpkAiWildHost $h)) { continue }
                $hostForm = 'literal'
                $first = $m.Groups['expr'].Value.Trim()
                if ($first -notmatch '^[A-Za-z_$][A-Za-z0-9_$.]{0,23}$') { $first = '<port expression>' }
            } elseif ($m.Groups['bare'].Success) {
                # No port literal and no address: this says something only as the listen call
                # of the code that registers the model API routes, and only when the name
                # reads as a port (.listen(callback) is an event subscription).
                $first = $m.Groups['bare'].Value
                if (-not $near -or $first.IndexOf('port', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
                if ($first.Length -gt 24) { $first = '<port expression>' }
                $hostForm = 'none'
            } else { continue }
            # Only an address literal is printed; any other host text is left out.
            if ($hostForm -eq 'literal' -and ($h -notmatch '^[A-Za-z0-9.:\[\]*_-]{1,45}$')) { $h = ''; $hostForm = 'expr' }
            $show = ".listen($first)"
            if ($hostForm -eq 'literal') { $show = ".listen($first, $h)" }
            elseif ($hostForm -eq 'expr') { $show = ".listen($first, ...)" }
            Add-TcpkAiBind -Acc $Acc -Kind 'listen' -BindHost $h -Port $p -Wild (Test-TcpkAiWildHost $h) -Show $show -Near $near -HostForm $hostForm
        }
    } catch { $Acc.Errors++ }

    # --- loopback host on a known inference port ---
    foreach ($needle in @('localhost:', '127.0.0.1:', '[::1]:')) {
        if ($Acc.Loops.Count -ge 20) { break }
        try {
            foreach ($m in @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.Loop -Before 10 -After 72 -MaxHits 5000)) {
                $h = $m.Groups['host'].Value.ToLowerInvariant()
                $p = $m.Groups['port'].Value
                $isUrl = $m.Groups['scheme'].Success
                $show = "${h}:$p"
                if ($isUrl) { $show = $m.Groups['scheme'].Value.ToLowerInvariant() + "://${h}:$p" }
                # Path: the first path under /v1 or /api seen on this endpoint. Plain: the
                # endpoint was seen with no path at all (a base URL). An endpoint seen only
                # with some other path (/callback, /hmr) is not an inference endpoint.
                $path = ''
                if ($m.Groups['path'].Success) { $path = $m.Groups['path'].Value }
                $isApi = ($path -and ($path -match '^/(?:v1|api)(?:/|$)'))
                if (-not $Acc.Loops.ContainsKey($show)) {
                    if ($Acc.Loops.Count -ge 20) { break }
                    $Acc.Loops[$show] = [pscustomobject]@{ Url = [bool]$isUrl; BindHost = $h; Port = $p; Show = $show; Path = ''; Plain = $false }
                }
                if (-not $path) { $Acc.Loops[$show].Plain = $true }
                elseif ($isApi -and -not $Acc.Loops[$show].Path) { $Acc.Loops[$show].Path = $path }
            }
        } catch { $Acc.Errors++ }
    }

    # --- engine C API symbols (PE only): three distinct names are enough ---
    if ($Symbols -and $Acc.Symbols.Count -lt 3) {
        foreach ($needle in @('ggml_', 'gguf_', 'llama_')) {
            if ($Acc.Symbols.Count -ge 3) { break }
            if ($needle -eq 'llama_' -and -not $hasLlama) { continue }
            try {
                foreach ($m in @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.Symbols -Before 1 -After 56 -MaxHits 400)) {
                    $Acc.Symbols[$m.Value] = $true
                    if ($Acc.Symbols.Count -ge 3) { break }
                }
            } catch { $Acc.Errors++ }
        }
    }
}

# Does this file hold anything a product marker would give context to?
function Test-TcpkAiWantsMarkers {
    param([Parameter(Mandatory)][hashtable]$Acc)
    return (($Acc.Routes.Count -gt 0) -or ($Acc.Binds.Count -gt 0) -or ($Acc.Loops.Count -gt 0))
}

# Does this PE hold something that only member names or an executable name can settle:
# a host variable held as two adjacent literals, or routes held as whole string literals?
function Test-TcpkAiWantsPeHints {
    param([Parameter(Mandatory)][hashtable]$Acc)
    if ($Acc.WideRoutes.Count -ge 2) { return $true }
    foreach ($b in $Acc.Binds.Values) { if ($b.Kind -eq 'env' -and $b.Tier -eq 'adjacent') { return $true } }
    return $false
}

# Member and executable names of a PE that settle the two rules above:
#   map:<name>     a .NET member that declares an HTTP route (MapPost, MapGet, ...)
#   member:<name>  a .NET member that sets a process environment variable
#   exe:<engine>   the engine's server executable is named in the file
function Add-TcpkAiPeHints {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][hashtable]$Acc)
    if ([string]::IsNullOrEmpty($Text)) { return }
    try {
        foreach ($name in $script:TcpkAiMapMembers) {
            $key = "map:$name"
            if (-not $Acc.Hints.ContainsKey($key) -and (Test-TcpkAiWholeToken -Text $Text -Needle $name)) { $Acc.Hints[$key] = $true }
        }
        foreach ($name in $script:TcpkAiSetterMembers) {
            $key = "member:$name"
            if (-not $Acc.Hints.ContainsKey($key) -and (Test-TcpkAiWholeToken -Text $Text -Needle $name)) { $Acc.Hints[$key] = $true }
        }
        foreach ($eng in @($script:TcpkAiEngineExe.Keys)) {
            $key = "exe:$eng"
            if ($Acc.Hints.ContainsKey($key)) { continue }
            foreach ($needle in $script:TcpkAiEngineExe[$eng]) {
                if (Test-TcpkAiWholeToken -Text $Text -Needle $needle) { $Acc.Hints[$key] = $true; break }
            }
        }
    } catch { $Acc.Errors++ }
}

# Ordinal needles that locate every product marker in its usual spellings. Each is a core
# shared by the forms the marker regex accepts ('llama' is inside ollama, llama.cpp and
# llama-server), so a handful of byte-compare passes replaces a case-insensitive regex sweep.
# The needles are exact-case, which is also what keeps a mixed-case run inside an unrelated
# identifier ("PollAmazon") or in compressed bytes from ever reaching the regex.
# Before / After size the window so the whole token and one character of context fit.
$script:TcpkAiMarkerNeedles = @(
    @{ Needles = @('llama', 'LLAMA', 'Llama', 'LLama');           Before = 2; After = 12; Max = 20000 }
    @{ Needles = @('studio', 'Studio', 'STUDIO');                 Before = 5; After = 2;  Max = 5000 }
    @{ Needles = @('4all', '4All', '4ALL');                       Before = 4; After = 2;  Max = 5000 }
    @{ Needles = @('nything', 'NYTHING');                         Before = 3; After = 8;  Max = 5000 }
    @{ Needles = @('jan.ai', 'janhq', 'cortex');                  Before = 1; After = 8;  Max = 5000 }
    @{ Needles = @('kobold', 'Kobold', 'KOBOLD');                 Before = 1; After = 6;  Max = 5000 }
)

# Product markers, as whole tokens. A marker names the product of a port and, for port
# 11434 only, ties a bind to that product. It never establishes a role on its own.
function Add-TcpkAiMarkers {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][hashtable]$Acc)
    if ([string]::IsNullOrEmpty($Text)) { return }
    $rx = Get-TcpkAiRegexSet
    $names = @($rx.MarkerNames)
    foreach ($g in $script:TcpkAiMarkerNeedles) {
        foreach ($needle in $g.Needles) {
            try {
                foreach ($m in @(Find-TcpkAiMatches -Text $Text -Needle $needle -Rx $rx.Markers -Before $g.Before -After $g.After -MaxHits $g.Max)) {
                    foreach ($k in $names) { if ($m.Groups[$k].Success) { $Acc.Markers[$k] = $true } }
                }
            } catch { $Acc.Errors++ }
        }
    }
    if (-not $Acc.Markers.ContainsKey('gguf')) {
        try {
            if (@(Find-TcpkAiMatches -Text $Text -Needle '.gguf' -Rx $rx.Gguf -Before 0 -After 2 -MaxHits 200).Count -gt 0) { $Acc.Markers['gguf'] = $true }
        } catch { $Acc.Errors++ }
    }
}

# JavaScript text to analyse. Comments are stripped with the project helper so a
# commented-out bind is not reported -- but ONLY where that helper is safe. On a minified or
# obfuscated bundle (megabytes on one line) its line-comment rule deletes everything after a
# '//' that sits inside a string literal: the real LM Studio main bundle loses 68% of its
# text and five of its six model API routes. Such a bundle carries next to no comments, so
# it is analysed as-is. The test is line density: under one line break per 300 characters
# is a bundle, anything denser is ordinary source, where the same rule can cost at most the
# rest of one short line.
function Get-TcpkAiJsCode {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $limit = [int][Math]::Floor($Text.Length / 300) + 1
    $lines = 0
    $pos = 0
    while ($lines -le $limit -and $pos -lt $Text.Length) {
        $pos = $Text.IndexOf([char]10, $pos)
        if ($pos -lt 0) { break }
        $lines++
        $pos++
    }
    if ($lines -le $limit) { return $Text }
    try { return (Get-TcpkJsCodeOnly $Text) } catch { return $Text }
}

# Remove every $Open ... $Close block. Ordinal searches only, one pass: an opener with no
# closer ends the work, so a file full of unclosed openers (template text such as "<#if")
# costs one scan. A lazy regex ('(?s)<#.*?#>') rescans to the end of the file from every
# such opener: 17 s on 312 KB of templates, and the regex timeout at 1.9 MB.
function Remove-TcpkAiBlocks {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Open, [Parameter(Mandatory)][string]$Close)
    $ord = [System.StringComparison]::Ordinal
    $i = $Text.IndexOf($Open, $ord)
    if ($i -lt 0) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    while ($i -ge 0) {
        $j = $Text.IndexOf($Close, $i + $Open.Length, $ord)
        if ($j -lt 0) { break }
        [void]$sb.Append($Text, $pos, $i - $pos)
        [void]$sb.Append(' ')
        $pos = $j + $Close.Length
        $i = $Text.IndexOf($Open, $pos, $ord)
    }
    [void]$sb.Append($Text, $pos, $Text.Length - $pos)
    return $sb.ToString()
}

# Remove /* ... */ comments from JSON-with-comments. An opener inside a string value (a
# glob such as "src/*.js") is not a comment: it is one when the double quotes before it on
# its line are balanced. On a very long line (minified JSON, which carries no comments)
# nothing is removed.
function Remove-TcpkAiJsonBlockComments {
    param([Parameter(Mandatory)][string]$Text)
    $ord = [System.StringComparison]::Ordinal
    $i = $Text.IndexOf('/*', $ord)
    if ($i -lt 0) { return $Text }
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    $guard = 0
    while ($i -ge 0) {
        $guard++
        if ($guard -gt 5000) { break }
        $from = 0
        if ($i -gt 0) { $from = $Text.LastIndexOfAny($script:TcpkAiCrLf, $i - 1) + 1 }
        $inString = $true
        if (($i - $from) -le 2048) {
            $quotes = 0
            foreach ($qm in [regex]::Matches($Text.Substring($from, $i - $from), '\\.|"')) { if ($qm.Value -eq '"') { $quotes++ } }
            $inString = (($quotes % 2) -eq 1)
        }
        if ($inString) { $i = $Text.IndexOf('/*', $i + 2, $ord); continue }
        $j = $Text.IndexOf('*/', $i + 2, $ord)
        if ($j -lt 0) { break }
        [void]$sb.Append($Text, $pos, $i - $pos)
        [void]$sb.Append(' ')
        $pos = $j + 2
        $i = $Text.IndexOf('/*', $pos, $ord)
    }
    [void]$sb.Append($Text, $pos, $Text.Length - $pos)
    return $sb.ToString()
}

# Configuration / launcher text to analyse: comments removed, so a commented-out example
# (# OLLAMA_HOST=...) is not read as active configuration.
#   whole-line comments   #  ;  //  ::  rem  @rem   (rem also when it is the whole line)
#   block comments        <!-- --> in .config / .xml,  <# #> in .ps1,  /* */ in .json / .jsonc
# A comment that follows active text on the same line is handled where a signal is
# judged (Test-TcpkAiTrailingComment).
# With no file name every style is applied.
function Get-TcpkAiConfigText {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Text, [string]$Name = '')
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $ext = ''
    $any = $true
    if ($Name) {
        $any = $false
        $lower = $Name.ToLowerInvariant()
        $dot = $lower.LastIndexOf('.')
        if ($dot -ge 0) { $ext = $lower.Substring($dot) }
    }
    try {
        $t = $Text
        if ($any -or $ext -eq '.config' -or $ext -eq '.xml') { $t = Remove-TcpkAiBlocks -Text $t -Open '<!--' -Close '-->' }
        if ($any -or $ext -eq '.ps1')  { $t = Remove-TcpkAiBlocks -Text $t -Open '<#' -Close '#>' }
        if ($any -or $ext -eq '.json' -or $ext -eq '.jsonc') { $t = Remove-TcpkAiJsonBlockComments -Text $t }
        return [regex]::Replace($t, '(?im)^[ \t]*(?:#|;|//|::|@?rem(?=[ \t\r\n]|\z))[^\r\n]*', '')
    } catch { return $Text }
}

# The table entry for a known engine server binary, or $null.
function Get-TcpkAiServerBinary {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Name)
    if (-not $Name) { return $null }
    $lower = $Name.ToLowerInvariant()
    foreach ($b in $script:TcpkAiServerBinaries) {
        if ([regex]::IsMatch($lower, $b.Rx)) { return $b }
    }
    return $null
}

function Test-TcpkAiServerBinaryName {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Name)
    return ($null -ne (Get-TcpkAiServerBinary -Name $Name))
}

# PE files that are never read by this check: framework and runtime code identified by name
# or by where it sits, none of which can be the listener. No file is skipped for its size
# alone; the one size test below is combined with the Chromium resource files that mark the
# folder as an Electron runtime folder.
function Test-TcpkAiSkipPe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [long]$Length = 0, [string]$FullName = '')
    if (Test-TcpkIsFrameworkFile $Name) { return $true }
    if (Test-TcpkIsNativeNoise $Name) { return $true }
    if (Test-TcpkIsChromiumRuntime -Name $Name) { return $true }
    $lower = $Name.ToLowerInvariant()
    if ($script:TcpkRuntimeHelperExes -contains $lower) { return $true }
    if ($lower -match $script:TcpkAiVendorRuntimeRx) { return $true }
    if ($Length -gt 80MB -and $lower.EndsWith('.exe') -and $FullName) {
        try {
            $parent = Split-Path -Parent $FullName
            if ($parent -and ((Test-Path -LiteralPath (Join-Path $parent 'icudtl.dat')) -or (Test-Path -LiteralPath (Join-Path $parent 'v8_context_snapshot.bin')))) { return $true }
        } catch { }
    }
    return $false
}

# Which non-PE files are read: first-party JavaScript (an .asar archive holds its scripts as
# plain text; an unpacked app tree is loose .js) and configuration / launcher files, where
# Electron and Tauri products keep the server and its bind. Returns 'js', 'config' or ''.
function Get-TcpkAiTextKind {
    [CmdletBinding()] param([AllowNull()][AllowEmptyString()][string]$Name, [AllowNull()][AllowEmptyString()][string]$FullName)
    if (-not $Name) { return '' }
    if ("$FullName" -match '(?i)[\\/]node_modules[\\/]') { return '' }     # third-party packages
    $lower = $Name.ToLowerInvariant()
    # A test or spec file (app.test.js, Server.Tests.ps1) carries fixtures, not the
    # product's listener or its configuration.
    if ($lower -match '(?:^|[._-])(?:tests?|spec)\.[a-z0-9]+$') { return '' }
    if ($lower.EndsWith('.asar')) { return 'js' }
    if ($lower -match '\.(?:js|cjs|mjs)$') { return 'js' }
    # A template is not active configuration.
    if ($lower -match '(?:^|[._-])(?:example|sample|template|dist)(?:[._-]|$)') { return '' }
    if ($lower -eq 'package-lock.json') { return '' }
    if ($lower -match '\.(?:jsonc?|ya?ml|toml|ini|cfg|conf|config|xml|properties|env|bat|cmd|ps1)$') { return 'config' }
    if ($lower -match '^\.env(?:\.[a-z0-9_.-]+)?$') { return 'config' }
    return ''
}

# Which assignment forms a file can hold (see Get-TcpkAiEnvTier).
function Get-TcpkAiTextStyle {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Kind, [AllowNull()][AllowEmptyString()][string]$Name)
    if ($Kind -eq 'pe') { return 'pe' }
    if ($Kind -eq 'js') { return 'js' }
    $lower = "$Name".ToLowerInvariant()
    if ($lower.EndsWith('.json') -or $lower.EndsWith('.jsonc')) { return 'json' }
    if ($lower.EndsWith('.config') -or $lower.EndsWith('.xml')) { return 'xml' }
    return 'line'
}

# Enumerate the script and configuration files under a path. Budget and heartbeat follow
# Get-TcpkPeFiles exactly: the walker is the GhostTree-safe one, the per-check deadline is
# tested once per file, and an early stop is recorded so Test-TcpkScanCoverage reports it.
# Consume this with the pipeline (| ForEach-Object), not a foreach statement: a foreach
# statement collects the whole sequence before the first iteration, which would run every
# budget test before any file is read.
function Get-TcpkAiTextFiles {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $emitted = 0
    $stopped = $false
    foreach ($f in (Get-TcpkChildItemSafe -Path $Path -File)) {
        $kind = Get-TcpkAiTextKind -Name "$($f.Name)" -FullName "$($f.FullName)"
        if (-not $kind) { continue }
        if (Test-TcpkCheckBudgetExpired) { $stopped = $true; break }
        $emitted++
        Write-TcpkHeartbeat -Component 'aiserver-text' -Index $emitted -Current $f.Name -CurrentBytes $f.Length
        [pscustomobject]@{ File = $f; Kind = $kind }
    }
    if ($stopped) { Add-TcpkScanSkip -Kind 'BudgetStopped' -ItemPath "$Path (after $emitted script/config file(s))" }
}

# Read one file and return its signal set. PE files are read in all three views (ASCII /
# UTF-8 metadata, and both UTF-16 alignments for .NET string literals); script and config
# files in UTF-8 only. Invoke-TcpkOnFileText streams a large file, so nothing is skipped for
# its size and any coverage loss is registered centrally.
function Read-TcpkAiFileSignals {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][ValidateSet('pe', 'js', 'config')][string]$Kind)
    $acc = New-TcpkAiSignalSet
    $leaf = ''
    try { $leaf = Split-Path -Leaf $Path } catch { $leaf = '' }
    $style = Get-TcpkAiTextStyle -Kind $Kind -Name $leaf
    $st = @{ Stop = $false; Calls = 0; Acc = $acc; Kind = $Kind; Style = $style; Leaf = $leaf; Views = (New-Object 'System.Collections.Generic.List[string]') }
    $utf8Only = ($Kind -ne 'pe')
    $onText = {
        param($Text, $Src, $S)
        $S.Calls++
        if (-not $Text) { return }
        $t = $Text
        if ($S.Kind -eq 'js') { $t = Get-TcpkAiJsCode -Text $Text }
        elseif ($S.Kind -eq 'config') { $t = Get-TcpkAiConfigText -Text $Text -Name $S.Leaf }
        if (-not $t) { return }
        $isPe = ($S.Kind -eq 'pe')
        $wide = ($isPe -and ("$Src".IndexOf('utf16') -ge 0))
        Add-TcpkAiSignals -Text $t -Acc $S.Acc -Symbols:$isPe -Style $S.Style -Wide:$wide
        # A '#N' source label means the file arrived in chunks (the fallback reader). A chunk
        # cannot be kept, so its markers and member names are taken now; a whole view is kept
        # and swept later, and only if the file turns out to need it.
        if ("$Src".IndexOf([char]'#') -ge 0) {
            Add-TcpkAiMarkers -Text $t -Acc $S.Acc
            if ($isPe) { Add-TcpkAiPeHints -Text $t -Acc $S.Acc }
        } else { $S.Views.Add($t) }
    }
    Invoke-TcpkOnFileText -Path $Path -State $st -Utf8Only:$utf8Only -OnText $onText
    if ($st.Calls -eq 0) {
        # Invoke-TcpkOnFileText sizes the file with Get-Item, which does not return a file
        # carrying the Hidden attribute unless -Force is given, so it hands over nothing.
        # The view reader opens the file by path and has no such limit; a hidden
        # configuration file is still configuration.
        $v = $null
        try { $v = Read-TcpkStringViews -Path $Path } catch { $v = $null }
        if ($v) {
            Register-TcpkViewCoverage -Views $v
            & $onText $v.Utf8 'utf8' $st
            if (-not $utf8Only) {
                & $onText $v.Utf16Le 'utf16le' $st
                & $onText $v.Utf16LeOdd 'utf16le-odd' $st
            }
        }
    }
    if (Test-TcpkAiWantsMarkers -Acc $acc) {
        foreach ($v in $st.Views) { Add-TcpkAiMarkers -Text $v -Acc $acc }
    }
    if ($Kind -eq 'pe' -and (Test-TcpkAiWantsPeHints -Acc $acc)) {
        foreach ($v in $st.Views) { Add-TcpkAiPeHints -Text $v -Acc $acc }
    }
    $first = ''
    if ($st.Views.Count -gt 0) { $first = $st.Views[0] }
    return [pscustomobject]@{ Acc = $acc; FirstView = $first }
}

# "the Ollama default port" when the product is established, else the neutral "a known
# inference port". A port number alone does not name a product. $Products is a set of
# marker keys: the file's own markers, or the server binaries under the scan root.
function Get-TcpkAiPortLabel {
    param([Parameter(Mandatory)][hashtable]$Products, [string]$Port)
    if ($script:TcpkAiPorts.ContainsKey("$Port")) {
        $e = $script:TcpkAiPorts["$Port"]
        if ($Products.ContainsKey($e.Marker)) { return "the $($e.Product) default port" }
    }
    return 'a known inference port'
}

function Format-TcpkAiList {
    param([string[]]$Items, [int]$Max = 4)
    $all = @($Items | Where-Object { $_ })
    if ($all.Count -le $Max) { return ($all -join ', ') }
    return ((@($all | Select-Object -First $Max) -join ', ') + " (+$($all.Count - $Max))")
}

# Decide what one file is. Returns:
#   Reasons        what makes it server evidence (empty when it is not)
#   AllInterfaces  the all-interfaces binds that qualify for HIGH
#   Pending        all-interfaces binds on a known inference port that nothing in this file
#                  ties to a model API (the scan root may still tie them, by port)
#   PendingEnv     engine host variable assignments that count only next to that engine's
#                  server binary
#   OtherWild      the other all-interfaces binds (shown, never used for severity)
#   OwnPorts       the known inference ports this file establishes a server on
#   Client         loopback inference endpoints (the client role)
function Resolve-TcpkAiFileRole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Acc, [string]$Name = '', [switch]$IsPe, [string]$Kind = '')

    $reasons    = New-Object 'System.Collections.Generic.List[string]'
    $allIf      = New-Object 'System.Collections.Generic.List[string]'
    $pending    = New-Object 'System.Collections.Generic.List[object]'
    $pendingEnv = New-Object 'System.Collections.Generic.List[object]'
    $pendingFlag = New-Object 'System.Collections.Generic.List[object]'
    # A launcher or classic configuration file (.bat .cmd .ps1 .env .ini .yaml .config
    # .xml ...) holds settings line by line. A script bundle, a JSON file and a compiled
    # file hold string literals, where the same text can be a help screen or a message.
    $style = 'pe'
    if ($Kind -and $Kind -ne 'pe') { $style = Get-TcpkAiTextStyle -Kind $Kind -Name $Name }
    $lineStyle = ($style -eq 'line' -or $style -eq 'xml')
    $other      = New-Object 'System.Collections.Generic.List[string]'
    $support    = New-Object 'System.Collections.Generic.List[string]'
    $client     = New-Object 'System.Collections.Generic.List[string]'
    $ownPorts   = @{}
    $noHostListen = $false

    $binary = $null
    if ($IsPe -and $Name) { $binary = Get-TcpkAiServerBinary -Name $Name }
    $binaryMarker = ''
    if ($binary) {
        $reasons.Add('inference server binary by file name')
        $binaryMarker = "$($binary.Marker)"
        foreach ($p in @($script:TcpkAiPorts.Keys)) { if ($binaryMarker -and $script:TcpkAiPorts[$p].Marker -eq $binaryMarker) { $ownPorts[$p] = $true } }
    }

    $routes   = @($Acc.Routes.Keys | Sort-Object)
    $patterns = @($Acc.Patterns.Keys | Sort-Object)
    $regCalls = @($Acc.RegCalls.Keys | Sort-Object)
    # Products that own a port first, so the name that matters is not the one cut off.
    $markers  = @($script:TcpkAiMarkerOrder | Where-Object { $Acc.Markers.ContainsKey($_) })
    $markerText = @($markers | ForEach-Object { $script:TcpkAiMarkerText[$_] })
    $wideRoutes = @($Acc.WideRoutes.Keys | Sort-Object)
    $mapMembers = @($script:TcpkAiMapMembers | Where-Object { $Acc.Hints.ContainsKey("map:$_") })

    # Does this file implement a model API by a rule of its own? (Rules 3, 4 and 5.)
    $routeRule = ($routes.Count -ge 2 -and $markers.Count -ge 1 -and $patterns.Count -ge 1)
    $mapRule   = ([bool]$IsPe -and $wideRoutes.Count -ge 2 -and $mapMembers.Count -ge 1)
    $modelApi  = $routeRule -or ($regCalls.Count -ge 1) -or $mapRule

    # Port 11434 is tied by its product's marker or by one of that product's routes.
    $ollamaTie = $Acc.Markers.ContainsKey('ollama')
    if (-not $ollamaTie) {
        foreach ($r in $routes) {
            if ($script:TcpkAiSpecificRoutes -contains $r) { $ollamaTie = $true }
            elseif ($r.StartsWith('/api/', [System.StringComparison]::Ordinal) -and -not $r.StartsWith('/api/v0/', [System.StringComparison]::Ordinal)) { $ollamaTie = $true }
        }
    }

    # A compiled assembly sets an environment variable through one of these members.
    $envSetter = $Acc.Hints.ContainsKey('member:SetEnvironmentVariable') -or $Acc.Hints.ContainsKey('member:get_EnvironmentVariables') -or
                 ($Acc.Hints.ContainsKey('member:get_Environment') -and $Acc.Hints.ContainsKey('member:set_Item'))

    # Engine forms first, so a plain host:port that repeats one of them is not listed twice.
    $rank = @{ env = 0; flag = 1; listen = 2; pair = 3; url = 4; hostport = 5 }
    $binds = @($Acc.Binds.Values | Sort-Object @{ Expression = { $rank[$_.Kind] } }, Show)
    $engineShows = @($binds | Where-Object { $_.Kind -eq 'env' } | ForEach-Object { $_.Show })
    $seenHostPort = @{}

    foreach ($b in $binds) {
        $form  = "$($b.Kind)"
        $port  = "$($b.Port)"
        $known = $script:TcpkAiPorts.ContainsKey($port)
        $tied  = $false
        if ($known) {
            if ($modelApi) { $tied = $true }
            elseif ($binaryMarker -and $script:TcpkAiPorts[$port].Marker -eq $binaryMarker) { $tied = $true }
            elseif ($port -eq '11434' -and $ollamaTie) { $tied = $true }
        }
        $label = Get-TcpkAiPortLabel -Products $Acc.Markers -Port $port

        if ($form -eq 'env' -or $form -eq 'flag') {
            # The engine binary's own strings describe its options. They are not the
            # target's configuration of it.
            if ($binary) { continue }
        }

        if ($form -eq 'env') {
            $tier = "$($b.Tier)"
            $eng  = "$($script:TcpkAiEnvEngine["$($b.Var)"])"
            if ($tier -eq 'literal') {
                # NAME=value as one whole string literal: a help screen that prints the
                # command has exactly this shape. Shown, never rated.
                $other.Add("$($b.Show) (inside a string literal, not rated)")
                continue
            }
            if ($tier -eq 'adjacent') {
                if (-not $envSetter) { continue }
                if ($eng -and $Acc.Hints.ContainsKey("exe:$eng")) {
                    $allIf.Add($b.Show)
                    $reasons.Add("all-interfaces bind $($b.Show) (engine host variable; name and value are adjacent string literals in a file that sets process environment variables and names the engine executable)")
                    if ($eng -eq 'ollama') { $ownPorts['11434'] = $true }
                } else { $pendingEnv.Add($b) }
            } elseif ($tier -eq 'solid') {
                if ($lineStyle) {
                    # An assignment line of a launcher or configuration file is a setting.
                    $allIf.Add($b.Show)
                    $reasons.Add("all-interfaces bind $($b.Show) (engine host variable)")
                    if ($eng -eq 'ollama') { $ownPorts['11434'] = $true }
                    if ($known) { $ownPorts[$port] = $true }
                } else {
                    # A key with a quoted value in a script bundle or a JSON file: held
                    # back, and counted only when that engine's server binary is under
                    # the scan root (Complete-TcpkAiScan).
                    $pendingEnv.Add($b)
                }
            } elseif ($tier -eq 'root') {
                $pendingEnv.Add($b)
            }
        }
        elseif ($form -eq 'flag') {
            if ("$($b.Tier)" -eq 'literal') {
                # The command inside one string literal: what a help screen prints.
                if ($b.Wild) { $other.Add("$($b.Show) (inside a string literal, not rated)") }
                continue
            }
            if ($lineStyle) {
                if ($b.Wild) {
                    $allIf.Add($b.Show)
                    $reasons.Add("all-interfaces bind $($b.Show) (engine host flag)")
                } else {
                    $reasons.Add("engine server launch $($b.Show)")
                }
            } else {
                # An argument array in a script bundle or a JSON file: held back until
                # that engine's server binary is found under the scan root.
                $pendingFlag.Add($b)
            }
        }
        elseif ($form -eq 'listen') {
            $hostForm = "$($b.HostForm)"
            # A call with no address is stated, never rated: HIGH needs a written address.
            $noHostText = ', no host argument'
            if ($Kind -eq 'js') { $noHostText = ', no host argument (a Node listener with no host accepts connections on every interface)' }
            if ($known -and $tied) {
                $ownPorts[$port] = $true
                # The same address written a second time (a constant, an options object
                # that also reads as a host / port pair) is one bind.
                if ($b.HostPort) { $seenHostPort[$b.HostPort] = $true }
                if ($b.Wild) {
                    $allIf.Add($b.Show)
                    $reasons.Add("all-interfaces listen call $($b.Show) on $label")
                } elseif ($hostForm -eq 'none') {
                    $noHostListen = $true
                    $reasons.Add("listen call $($b.Show) on $label$noHostText")
                } elseif ($hostForm -eq 'expr') {
                    $reasons.Add("listen call $($b.Show) on $label (the address argument is not a literal)")
                } else {
                    $reasons.Add("listen call $($b.Show) on $label")
                }
            } elseif ($b.Wild -and $b.Near) {
                # The server's own listen call: it sits next to the route registration.
                $allIf.Add($b.Show)
                $reasons.Add("all-interfaces listen call $($b.Show) next to the model API route registration")
            } elseif ($b.Near -and $hostForm -eq 'none') {
                $noHostListen = $true
                $reasons.Add("listen call $($b.Show) next to the model API route registration$noHostText")
            } elseif ($b.Near -and $hostForm -eq 'literal') {
                $reasons.Add("listen call $($b.Show) next to the model API route registration")
            } elseif ($b.Wild -and $known) {
                $pending.Add($b)
            } elseif ($b.Wild) {
                $other.Add($b.Show)
            }
        }
        else {
            # url / hostport / pair: always an all-interfaces host
            $dup = $false
            if ($b.HostPort) {
                foreach ($es in $engineShows) { if ($es.IndexOf($b.HostPort, [System.StringComparison]::Ordinal) -ge 0) { $dup = $true } }
                # http://0.0.0.0:11434 and 0.0.0.0:11434 are one bind: the first form seen wins.
                if ($seenHostPort.ContainsKey($b.HostPort)) { $dup = $true }
            }
            if ($dup) { continue }
            if ($b.HostPort) { $seenHostPort[$b.HostPort] = $true }
            # An address written as text is rated only as a value in a launcher or
            # configuration file, and only once a server on that port is established under
            # the scan root (Complete-TcpkAiScan). In a script bundle or a compiled file
            # the same text can be a message or a help screen, and a product name in the
            # same file does not change that, so there it is shown and never rated.
            if ($Kind -eq 'config' -and $known) {
                $pending.Add($b)
            } else {
                $other.Add($b.Show)
            }
        }
    }

    # Two or more whole-token routes, an engine marker, and a router-side path parameter.
    if ($routeRule) {
        $reasons.Add("model API routes $(Format-TcpkAiList -Items $routes -Max 4) with marker $(Format-TcpkAiList -Items $markerText -Max 4) and router path parameter $($patterns[0])")
    }

    # A route registration call in a server-only syntax.
    if ($regCalls.Count -ge 1) {
        $reasons.Add("model API route registration $(Format-TcpkAiList -Items $regCalls -Max 3)")
    }

    # Compiled .NET: the mapping member and the routes are separate strings in the file.
    if ($mapRule) {
        $reasons.Add("route-mapping member $(Format-TcpkAiList -Items $mapMembers -Max 3) with model API routes $(Format-TcpkAiList -Items $wideRoutes -Max 4) as string literals")
    }

    foreach ($l in @($Acc.Loops.Values | Sort-Object Show)) {
        $port = "$($l.Port)"
        if (-not $script:TcpkAiPorts.ContainsKey($port)) { continue }
        $entry = $script:TcpkAiPorts[$port]
        $hasMarker = $Acc.Markers.ContainsKey($entry.Marker)
        $labelled = "$($l.Show) ($($entry.Product) default port)"

        # Seen only with a path that is not under /v1 or /api: some other local service.
        if (-not $l.Plain -and -not $l.Path) { continue }

        # A model API route on the same endpoint. Only the route itself is ever printed,
        # never the rest of the path.
        $attached = ''
        if ($l.Path) {
            foreach ($r in $script:TcpkAiSpecificRoutes) {
                if (-not $attached -and $l.Path.StartsWith($r, [System.StringComparison]::Ordinal)) { $attached = $r }
            }
            if (-not $attached -and $port -eq '11434') {
                $nm = [regex]::Match($l.Path, '^/api/(?:generate|chat|tags|pull|push|show|embeddings|embed|ps)(?![A-Za-z0-9_-])')
                if ($nm.Success) { $attached = $nm.Value }
            }
        }

        if ($hasMarker -and -not $l.Url -and $patterns.Count -ge 1) {
            $ownPorts[$port] = $true
            $reasons.Add("host:port $labelled with router path parameter $($patterns[0])")
        } elseif ($hasMarker -and ($modelApi -or $port -eq '11434' -or $attached)) {
            # Shown next to server evidence only. For a development port the endpoint must
            # be in a file that implements the model API, or carry a model API route.
            $support.Add("loopback endpoint $labelled")
        }

        # Client endpoint. Port 11434 is used by one product, so that product's marker is
        # enough. 1234, 1337, 3001 and 4891 are also development ports (a dev-server URL
        # next to a provider name is not an inference endpoint): they need a model API
        # route on the same URL.
        if ($hasMarker -and $port -eq '11434') {
            $client.Add($labelled)
        } elseif ($attached) {
            if ($hasMarker) { $client.Add("$($l.Show)$attached (model API route on the $($entry.Product) default port)") }
            else { $client.Add("$($l.Show)$attached (model API route on a known inference port)") }
        }
    }

    return [pscustomobject]@{
        IsServer      = ($reasons.Count -gt 0)
        IsBinary      = ($null -ne $binary)
        BinaryMarker  = $binaryMarker
        ModelApi      = [bool]$modelApi
        Reasons       = $reasons.ToArray()
        AllInterfaces = $allIf.ToArray()
        Pending       = $pending.ToArray()
        PendingEnv    = $pendingEnv.ToArray()
        PendingFlag   = $pendingFlag.ToArray()
        OtherWild     = $other.ToArray()
        Support       = $support.ToArray()
        Client        = $client.ToArray()
        OwnPorts      = @($ownPorts.Keys)
        Markers       = @($markers)
        NoHostListen  = $noHostListen
        IsLibrary     = ([bool]$IsPe -and ($Acc.Symbols.Count -ge 3))
    }
}

function New-TcpkAiScanState {
    [CmdletBinding()] param([Parameter(Mandatory)]$Root)
    $full = "$($Root.FullName)"
    $base = $full.TrimEnd('\', '/')
    return @{
        RootFull  = $full
        RootBase  = $base
        IsDir     = [bool]$Root.PSIsContainer
        Servers   = (New-Object 'System.Collections.Generic.List[object]')
        Pending   = (New-Object 'System.Collections.Generic.List[object]')
        Clients   = (New-Object 'System.Collections.Generic.List[object]')
        Libraries = (New-Object 'System.Collections.Generic.List[object]')
    }
}

# Path of a file relative to the scan root, for Evidence. String arithmetic on purpose:
# Path.GetRelativePath does not exist on .NET Framework.
function Get-TcpkAiRelPath {
    param([Parameter(Mandatory)][hashtable]$Scan, [string]$FullName)
    if (-not $FullName) { return '' }
    if ($Scan.IsDir -and $Scan.RootBase -and $FullName.Length -gt ($Scan.RootBase.Length + 1) -and
        $FullName.StartsWith($Scan.RootBase, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $FullName.Substring($Scan.RootBase.Length).TrimStart('\', '/')
    }
    try { return (Split-Path -Leaf $FullName) } catch { return $FullName }
}

# Classify one enumerated file and record it in the scan state. Never throws.
function Add-TcpkAiFileEvidence {
    [CmdletBinding()]
    param([AllowNull()]$File, [Parameter(Mandatory)][ValidateSet('pe', 'js', 'config')][string]$Kind, [Parameter(Mandatory)][hashtable]$Scan)
    if (-not $File) { return }
    try {
        $name = "$($File.Name)"
        $full = "$($File.FullName)"
        if (-not $name -or -not $full) { return }
        $isPe = ($Kind -eq 'pe')
        $isBinary = $false
        if ($isPe) {
            $ext = "$($File.Extension)".ToLowerInvariant()
            if ($ext -notin '.dll', '.exe', '.node') { return }
            $isBinary = Test-TcpkAiServerBinaryName -Name $name
            if (-not $isBinary -and (Test-TcpkAiSkipPe -Name $name -Length ([long]$File.Length) -FullName $full)) { return }
        }

        $read = Read-TcpkAiFileSignals -Path $full -Kind $Kind
        $role = Resolve-TcpkAiFileRole -Acc $read.Acc -Name $name -IsPe:$isPe -Kind $Kind
        $hasPending = ((@($role.Pending).Count + @($role.PendingEnv).Count + @($role.PendingFlag).Count) -gt 0)
        if (-not ($role.IsServer -or $role.IsLibrary -or $hasPending -or @($role.Client).Count -gt 0)) { return }

        # The Electron main executable is the Chromium runtime, not the vendor's code. It is
        # normally skipped by name or folder before it is read; this catches one that is not.
        if ($isPe -and -not $isBinary -and ($role.IsServer -or $hasPending -or @($role.Client).Count -gt 0)) {
            if (Test-TcpkIsChromiumRuntime -Name $name -Text $read.FirstView) { return }
        }

        $rel = Get-TcpkAiRelPath -Scan $Scan -FullName $full
        $depth = 0
        foreach ($ch in $rel.ToCharArray()) { if ($ch -eq '\' -or $ch -eq '/') { $depth++ } }
        $rec = [pscustomobject]@{
            Name          = $name
            Full          = $full
            Rel           = $rel
            Depth         = $depth
            Kind          = $Kind
            IsBinary      = $role.IsBinary
            BinaryMarker  = "$($role.BinaryMarker)"
            Reasons       = @($role.Reasons)
            AllInterfaces = @($role.AllInterfaces)
            Pending       = @($role.Pending)
            PendingEnv    = @($role.PendingEnv)
            PendingFlag   = @($role.PendingFlag)
            OtherWild     = @($role.OtherWild)
            Support       = @($role.Support)
            Client        = @($role.Client)
            OwnPorts      = @($role.OwnPorts)
            Markers       = @($role.Markers)
            NoHostListen  = [bool]$role.NoHostListen
        }
        if ($role.IsServer) { $Scan.Servers.Add($rec) }
        else {
            # A file can be more than one of these; each list answers its own question.
            if ($hasPending) { $Scan.Pending.Add($rec) }
            if ($role.IsLibrary) { $Scan.Libraries.Add($rec) }
            elseif (@($role.Client).Count -gt 0) { $Scan.Clients.Add($rec) }
        }
    } catch { }
}

# Close the scan: decide, for the scan root as a whole, what to do with the binds a file
# could not tie by itself.
#   * An all-interfaces bind on a known inference port counts when a server on that same
#     port is established under the root: the server binary of the product that owns the
#     port (ollama.exe next to a settings file that says host 0.0.0.0 port 11434), or a
#     file that implements the model API and listens on that port. A product NAME in a
#     server file establishes nothing: a launcher that lists remote providers does not
#     turn a development listener elsewhere in the tree into one of those products.
#   * An engine host variable assignment, and an engine command line with its host flag,
#     count when that engine's server binary is under the root. Neither is ever rated from
#     the file that holds it alone: both are settings FOR a server, not a server.
# Anything else is shown as an untied bind in a file that is server evidence for another
# reason, and dropped everywhere else.
# Returns the server evidence files, ordered for Evidence.
function Complete-TcpkAiScan {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Scan)
    $servers = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $Scan.Servers) { $servers.Add($s) }
    if ($servers.Count -eq 0) { return @() }

    $rootPorts = @{}
    $rootBinaries = @{}
    foreach ($s in $servers) {
        foreach ($p in @($s.OwnPorts)) { if ($p) { $rootPorts["$p"] = $true } }
        if ($s.BinaryMarker) { $rootBinaries["$($s.BinaryMarker)"] = $true }
    }

    $candidates = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $servers) { $candidates.Add($s) }
    foreach ($p in $Scan.Pending) { $candidates.Add($p) }

    foreach ($c in $candidates) {
        $pend = @($c.Pending)
        $pendEnv = @($c.PendingEnv)
        $pendFlag = @($c.PendingFlag)
        if ($pend.Count -eq 0 -and $pendEnv.Count -eq 0 -and $pendFlag.Count -eq 0) { continue }
        $isServerFile = (@($c.Reasons).Count -gt 0)
        $tied = $false
        foreach ($e in $pendEnv) {
            $eng = "$($script:TcpkAiEnvEngine["$($e.Var)"])"
            if ($eng -and $rootBinaries.ContainsKey($eng)) {
                $c.AllInterfaces = @($c.AllInterfaces) + @("$($e.Show)")
                $c.Reasons = @($c.Reasons) + @("all-interfaces bind $($e.Show) (engine host variable; the $($script:TcpkAiMarkerText[$eng]) server binary is under the scan root)")
                $tied = $true
            }
        }
        foreach ($f in $pendFlag) {
            $eng = "$($f.Var)"
            if ($eng -and $rootBinaries.ContainsKey($eng)) {
                $prod = "$($script:TcpkAiMarkerText[$eng])"
                if (-not $prod) { $prod = $eng }
                if ($f.Wild) {
                    $c.AllInterfaces = @($c.AllInterfaces) + @("$($f.Show)")
                    $c.Reasons = @($c.Reasons) + @("all-interfaces bind $($f.Show) (engine host flag; the $prod server binary is under the scan root)")
                } else {
                    $c.Reasons = @($c.Reasons) + @("engine server launch $($f.Show) (the $prod server binary is under the scan root)")
                }
                $tied = $true
            }
        }
        foreach ($b in $pend) {
            $port = "$($b.Port)"
            if ($rootPorts.ContainsKey($port)) {
                $products = @{}
                foreach ($k in @($c.Markers)) { if ($k) { $products["$k"] = $true } }
                foreach ($k in @($rootBinaries.Keys)) { $products["$k"] = $true }
                $label = Get-TcpkAiPortLabel -Products $products -Port $port
                $what = 'all-interfaces bind'
                if ("$($b.Kind)" -eq 'listen') { $what = 'all-interfaces listen call' }
                $c.AllInterfaces = @($c.AllInterfaces) + @("$($b.Show)")
                $c.Reasons = @($c.Reasons) + @("$what $($b.Show) on $label (a server on that port is established elsewhere under the scan root)")
                $tied = $true
            } elseif ($isServerFile) {
                $c.OtherWild = @($c.OtherWild) + @("$($b.Show)")
            }
        }
        $c.Pending = @()
        $c.PendingEnv = @()
        $c.PendingFlag = @()
        if ($tied -and -not $isServerFile) { $servers.Add($c) }
    }

    return @($servers.ToArray() | Sort-Object `
        @{ Expression = { if (@($_.AllInterfaces).Count -gt 0) { 0 } else { 1 } } },
        @{ Expression = { if ($_.IsBinary) { 0 } else { 1 } } },
        Depth, Rel)
}

# Evidence text for the server finding: which files, and which signals in each. Files that
# carry a qualifying all-interfaces bind come first so the value that justifies HIGH is the
# first thing read.
function Format-TcpkAiServerEvidence {
    [CmdletBinding()] param([Parameter(Mandatory)][object[]]$Files, [int]$MaxFiles = 4, [int]$MaxLength = 1400)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $parts.Add("server evidence in $($Files.Count) file(s)")
    $shown = 0
    foreach ($f in $Files) {
        if ($shown -ge $MaxFiles) { break }
        $bits = New-Object 'System.Collections.Generic.List[string]'
        foreach ($r in @($f.Reasons | Select-Object -First 5)) { $bits.Add($r) }
        foreach ($s in @($f.Support | Select-Object -First 2)) { $bits.Add($s) }
        $ow = @($f.OtherWild | Select-Object -First 3)
        if ($ow.Count -gt 0) { $bits.Add('all-interfaces address text seen but not rated: ' + ($ow -join ', ')) }
        $parts.Add("$($f.Rel): " + ($bits.ToArray() -join '; '))
        $shown++
    }
    if ($Files.Count -gt $shown) { $parts.Add("(+$($Files.Count - $shown) more file(s))") }
    $ev = $parts.ToArray() -join ' | '
    if ($ev.Length -gt $MaxLength) { $ev = $ev.Substring(0, $MaxLength) + ' ...' }
    return (Get-TcpkRedact $ev)
}

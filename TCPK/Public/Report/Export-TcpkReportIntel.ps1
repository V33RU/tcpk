function Export-TcpkReportIntel {
<#
.SYNOPSIS
    Export a self-contained "program intelligence" report (intel.html) -- a modern,
    offline, single-file dashboard that EXPLAINS the findings (not just lists them).

.DESCRIPTION
    A no-server, double-click HTML app: dark dashboard with severity + confidence
    breakdown, a recon snapshot (classified endpoint map), and one "intelligence card"
    per finding showing the evidence ladder (Inferred -> Confirmed (IL) -> Confirmed
    (dynamic)), CWE / ATT&CK / computed CVSS, why we believe it, how to verify, and the
    fix. All data, CSS and JS are embedded -- no CDN, fully portable. Live filter + search.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.PARAMETER OutFile
    Path to write intel.html.

.PARAMETER Target
    Optional target string (shown in the header).

.PARAMETER Profile
    Optional Get-TcpkTargetProfile output (drives the identity + recon snapshot).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$Target = '',
        [object]$Profile = $null
    )
    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        # Build the shared intelligence model and serialize it. Get-TcpkIntelModel is the
        # single source of truth shared with the live web control panel (Start-TcpkWebUi),
        # so the offline report and the live panel never drift on a finding's data shape.
        $root = Get-TcpkIntelModel -Findings $all.ToArray() -Target $Target -Profile $Profile
        $json = Protect-TcpkJsonForScript ($root | ConvertTo-Json -Depth 8 -Compress)

        $html = $script:TCPK_INTEL_TEMPLATE.Replace('__TCPK_DATA__', $json)

        [System.IO.File]::WriteAllText($OutFile, $html, (New-Object System.Text.UTF8Encoding($false)))
        Write-TcpkInfo "Intel report written: $OutFile ($($all.Count) findings)"
    }
}

# The static HTML/CSS/JS shell (ASCII only). Data is injected at __TCPK_DATA__. Kept in a
# script-scope variable so the function body stays readable; single-quoted so nothing is
# interpolated by PowerShell.
$script:TCPK_INTEL_TEMPLATE = @'
<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TCPK Intelligence Report</title>
<style>
:root{--bg:#0b0e14;--panel:#161b22;--panel2:#1c2230;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--dim:#6e7681;
--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#3fb950;--info:#8b949e;--il:#3fb950;--dyn:#39c5cf;--llm:#bc8cff;--inf:#8b949e;--accent:#56d364;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,Arial,sans-serif}
.wrap{max-width:1140px;margin:0 auto;padding:22px}
a{color:#58a6ff}
.hd{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:14px;margin-bottom:18px}
.brand{font:700 26px Consolas,monospace}.brand span{color:var(--accent)}
.sub{color:var(--muted);font-size:13px;margin-top:2px}
.metar{color:var(--dim);font:12px Consolas,monospace;text-align:right}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.stat b{font:700 30px Consolas,monospace;display:block;line-height:1.1}
.stat small{color:var(--muted);font-size:12px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:16px}
.panel h3{margin:0 0 10px;font:700 13px Consolas,monospace;color:var(--muted);letter-spacing:.04em}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;border:1px solid var(--border)}
.sevbar i{display:block}
.legend{display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:12px;color:var(--muted)}
.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
.confrow{display:flex;gap:10px;flex-wrap:wrap}
.confpill{border:1px solid var(--border);border-radius:20px;padding:4px 11px;font:12px Consolas,monospace;background:var(--panel2)}
.recon{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px}
.eprow{display:flex;align-items:center;gap:8px;font:12px Consolas,monospace;padding:4px 0;border-bottom:1px solid #21262d}
.cat{font-size:10px;padding:1px 7px;border-radius:9px;border:1px solid var(--border);color:var(--muted)}
.cat.telemetry{color:#d29922;border-color:#d29922}.cat.cloud-storage{color:#39c5cf;border-color:#39c5cf}
.cat.auth{color:#bc8cff;border-color:#bc8cff}.cat.cdn{color:#58a6ff;border-color:#58a6ff}.cat.update{color:#8b949e}
.cat.first-party{color:#56d364;border-color:#3fb950}
.flag{font-size:10px;color:var(--crit)}
.bar2{position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--border);margin-bottom:14px}
.chip{cursor:pointer;user-select:none;border:1px solid var(--border);border-radius:20px;padding:5px 12px;font:12px Consolas,monospace;color:var(--muted);background:var(--panel)}
.chip.on{color:var(--bg);font-weight:700}
.chip.crit.on{background:var(--crit);border-color:var(--crit)}.chip.high.on{background:var(--high);border-color:var(--high)}
.chip.med.on{background:var(--med);border-color:var(--med)}.chip.low.on{background:var(--low);border-color:var(--low)}
.chip.info.on{background:var(--info);border-color:var(--info)}
.chip.conf.on{background:var(--accent);border-color:var(--accent)}
.search{flex:1;min-width:160px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);padding:7px 11px;font:13px Consolas,monospace}
.card{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:10px;margin-bottom:10px;overflow:hidden}
.card.crit{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}.card.med{border-left-color:var(--med)}
.card.low{border-left-color:var(--low)}.card.info{border-left-color:var(--info)}
.head{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;flex-wrap:wrap}
.pill{font:700 10px Consolas,monospace;padding:2px 8px;border-radius:5px;color:#0b0e14}
.pill.crit{background:var(--crit)}.pill.high{background:var(--high)}.pill.med{background:var(--med)}.pill.low{background:var(--low)}.pill.info{background:var(--info)}
.badge{font:11px Consolas,monospace;padding:2px 8px;border-radius:12px;border:1px solid}
.badge.il{color:var(--il);border-color:var(--il)}.badge.dyn{color:var(--dyn);border-color:var(--dyn)}
.badge.llm{color:var(--llm);border-color:var(--llm)}.badge.inf{color:var(--inf);border-color:var(--border)}
.cvss{font:11px Consolas,monospace;color:var(--muted)}
.ttl{font-weight:600;flex:1;min-width:200px}
.rule{font:11px Consolas,monospace;color:var(--dim)}
.body{display:none;padding:0 14px 14px;border-top:1px solid #21262d}
.card.open .body{display:block}
.sec{margin-top:12px}.sec h4{margin:0 0 5px;font:700 11px Consolas,monospace;color:var(--muted);letter-spacing:.04em}
.sec p{margin:0;color:#c9d1d9}
pre.ev{background:#010409;border:1px solid var(--border);border-radius:7px;padding:10px;overflow:auto;font:12px Consolas,monospace;color:#c9d1d9;white-space:pre-wrap;word-break:break-word}
.kv{font:11px Consolas,monospace;color:var(--muted)}.kv b{color:#c9d1d9}
.empty{color:var(--muted);text-align:center;padding:30px}
.foot{color:var(--dim);font:11px Consolas,monospace;text-align:center;margin-top:24px;padding-top:14px;border-top:1px solid var(--border)}
</style></head><body><div class="wrap" id="app"></div>
<script id="tcpk-data" type="application/json">__TCPK_DATA__</script>
<script>
(function(){
  var D; try{ D=JSON.parse(document.getElementById('tcpk-data').textContent); }catch(e){ D={meta:{},summary:{severity:{},confidence:{}},findings:[]}; }
  function arr(x){ return Array.isArray(x)?x:(x?[x]:[]); }
  function esc(s){ s=(s==null?'':String(s)); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  var SEV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  var SC={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};
  var SCOL={CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'};
  var findings=arr(D.findings);
  function confClass(c){ c=c||''; if(c.indexOf('IL')>=0)return'il'; if(c.indexOf('dynamic')>=0)return'dyn'; if(c.indexOf('LLM')>=0)return'llm'; return'inf'; }
  function confWhy(c){ c=c||'';
    if(c.indexOf('dynamic')>=0)return'Demonstrated at runtime -- TCPK observed the behaviour, not just matched a pattern.';
    if(c.indexOf('(IL)')>=0)return'Proven from the compiled bytecode (Mono.Cecil): reachable + the dangerous input actually flows in.';
    if(c.indexOf('LLM')>=0)return'An AI read the code and judged it (advisory -- the deterministic evidence still stands).';
    if(c==='Confirmed')return'A verifiable fact (e.g. signature status, a PE flag, a file present).';
    if(c.indexOf('Likely-FP')>=0)return'Down-graded: the API is never actually invoked, or only with constant arguments.';
    return'Pattern / string match -- presence, not proof. Review or run the dynamic/IL verifier.'; }
  var st={sev:{},conf:null,q:''}; SEV.forEach(function(s){st.sev[s]=true;});

  function h(){ var m=D.meta||{}; var id=D.identity||null;
    var s='<div class="hd"><div><div class="brand">TC<span>PK</span> intelligence</div>'
      +'<div class="sub">'+esc(m.target||'(target)')+(id&&id.name?' &middot; '+esc(id.name)+' '+esc(id.version):'')+'</div></div>'
      +'<div class="metar">v'+esc(m.version)+'<br>'+esc(m.generated)+' UTC<br>'+esc(m.total)+' findings</div></div>';
    return s; }

  function dash(){ var sv=(D.summary&&D.summary.severity)||{}; var total=0; SEV.forEach(function(s){total+=(sv[s]||0);});
    var stats='<div class="grid">';
    SEV.forEach(function(s){ stats+='<div class="stat"><b style="color:'+SCOL[s]+'">'+(sv[s]||0)+'</b><small>'+s+'</small></div>'; });
    stats+='</div>';
    var bar='<div class="panel"><h3>SEVERITY DISTRIBUTION</h3><div class="sevbar">';
    SEV.forEach(function(s){ var n=sv[s]||0; var w=total?(n/total*100):0; if(w>0) bar+='<i style="width:'+w+'%;background:'+SCOL[s]+'" title="'+s+': '+n+'"></i>'; });
    bar+='</div><div class="legend">';
    SEV.forEach(function(s){ bar+='<span><span class="dot" style="background:'+SCOL[s]+'"></span>'+s+' '+(sv[s]||0)+'</span>'; });
    bar+='</div></div>';
    var cf=(D.summary&&D.summary.confidence)||{}; var crow='<div class="panel"><h3>EVIDENCE / CONFIDENCE</h3><div class="confrow">';
    Object.keys(cf).forEach(function(k){ crow+='<span class="confpill" title="'+esc(confWhy(k))+'">'+esc(k)+': '+cf[k]+'</span>'; });
    crow+='</div><div class="legend" style="margin-top:8px">Hover a confidence tag to see how that finding was proven. The ladder: Inferred (pattern) &rarr; Confirmed (IL) (bytecode proof) &rarr; Confirmed (dynamic) (observed at runtime).</div></div>';
    return stats+bar+crow; }

  function recon(){ var r=D.recon; if(!r) return''; var eps=arr(r.endpoints);
    var s='<div class="panel"><h3>RECON &middot; ATTACK SURFACE</h3>';
    s+='<div class="kv" style="margin-bottom:8px">endpoints <b>'+eps.length+'</b> &middot; listening ports <b>'+arr(r.ports).length+'</b> &middot; protocol handlers <b>'+(r.handlers||0)+'</b> &middot; named pipes <b>'+(r.pipes||0)+'</b> &middot; COM <b>'+(r.com||0)+'</b></div>';
    if(eps.length){ s+='<div>'; eps.slice(0,40).forEach(function(e){ var cat=(e.Category||'first-party');
      s+='<div class="eprow"><span class="cat '+cat+'">'+esc(cat)+'</span><span>'+esc(e.Host)+'</span><span style="color:var(--dim)">'+esc(e.Schemes||'')+'</span>';
      arr(e.Flags).forEach(function(f){ s+=' <span class="flag">'+esc(f)+'</span>'; }); s+='</div>'; }); s+='</div>'; }
    s+='</div>'; return s; }

  function filters(){ var s='<div class="bar2">';
    SEV.forEach(function(sv){ s+='<span class="chip '+SC[sv]+(st.sev[sv]?' on':'')+'" data-sev="'+sv+'">'+sv+'</span>'; });
    var cf=(D.summary&&D.summary.confidence)||{};
    Object.keys(cf).forEach(function(k){ s+='<span class="chip conf'+(st.conf===k?' on':'')+'" data-conf="'+esc(k)+'">'+esc(k)+'</span>'; });
    s+='<input class="search" id="q" placeholder="search title / rule / file / evidence..." value="'+esc(st.q)+'"/></div>';
    return s; }

  function match(f){ if(!st.sev[f.sev])return false; if(st.conf&&f.conf!==st.conf)return false;
    if(st.q){ var q=st.q.toLowerCase(); var hay=((f.title||'')+' '+(f.rule||'')+' '+(f.file||'')+' '+(f.evidence||'')+' '+(f.desc||'')).toLowerCase(); if(hay.indexOf(q)<0)return false; }
    return true; }

  function card(f,i){ var sc=SC[f.sev]||'info'; var cwe=arr(f.cwe).join(', ');
    var s='<div class="card '+sc+'" data-i="'+i+'"><div class="head">'
      +'<span class="pill '+sc+'">'+esc(f.sev)+'</span>'
      +'<span class="badge '+confClass(f.conf)+'" title="'+esc(confWhy(f.conf))+'">'+esc(f.conf)+'</span>'
      +(f.cvss?'<span class="cvss">'+esc(f.cvss)+'</span>':'')
      +'<span class="ttl">'+esc(f.title)+'</span>'
      +'<span class="rule">'+esc(f.rule)+'</span></div>'
      +'<div class="body">';
    if(f.desc) s+='<div class="sec"><h4>WHAT &amp; WHY</h4><p>'+esc(f.desc)+'</p></div>';
    if(f.evidence) s+='<div class="sec"><h4>EVIDENCE</h4><pre class="ev">'+esc(f.evidence)+'</pre></div>';
    if(arr(f.affected).length) s+='<div class="sec"><h4>AFFECTED ('+arr(f.affected).length+')</h4><pre class="ev">'+esc(arr(f.affected).join('\n'))+'</pre></div>';
    if(f.verify) s+='<div class="sec"><h4>HOW TO VERIFY</h4><pre class="ev">'+esc(f.verify)+'</pre></div>';
    if(f.fix) s+='<div class="sec"><h4>FIX</h4><p>'+esc(f.fix)+'</p></div>';
    s+='<div class="sec"><div class="kv">'+(cwe?'CWE: <b>'+esc(cwe)+'</b> &middot; ':'')+(f.attack?'ATT&amp;CK: <b>'+esc(f.attack)+'</b> &middot; ':'')+(f.tasvs?'TASVS: <b>'+esc(f.tasvs)+'</b> &middot; ':'')+(f.owaspDa?'OWASP: <b>'+esc(f.owaspDa)+'</b> &middot; ':'')+'file: <b>'+esc(f.file||'-')+'</b></div></div>';
    s+='</div></div>'; return s; }

  function list(){ var shown=findings.filter(match);
    if(!shown.length) return '<div class="empty">No findings match the current filter.</div>';
    var s=''; for(var i=0;i<findings.length;i++){ if(match(findings[i])) s+=card(findings[i],i); } return s; }

  function render(){ var app=document.getElementById('app');
    app.innerHTML=h()+dash()+recon()+filters()+'<div id="list">'+list()+'</div>'
      +'<div class="foot">TCPK intelligence report &middot; evidence over assertion &middot; generated offline, no server</div>';
    wire(); }
  function relist(){ document.getElementById('list').innerHTML=list(); wireCards(); }
  function wireCards(){ var cs=document.querySelectorAll('.card .head'); for(var i=0;i<cs.length;i++){ cs[i].onclick=function(){ this.parentNode.classList.toggle('open'); }; } }
  function wire(){
    var chips=document.querySelectorAll('.chip');
    for(var i=0;i<chips.length;i++){ chips[i].onclick=function(){ var sv=this.getAttribute('data-sev'); var cf=this.getAttribute('data-conf');
      if(sv){ st.sev[sv]=!st.sev[sv]; this.classList.toggle('on'); }
      else if(cf!=null){ if(st.conf===cf){ st.conf=null; } else { st.conf=cf; } var cc=document.querySelectorAll('.chip.conf'); for(var j=0;j<cc.length;j++){ cc[j].classList.toggle('on', cc[j].getAttribute('data-conf')===st.conf); } }
      relist(); }; }
    var q=document.getElementById('q'); if(q){ q.oninput=function(){ st.q=this.value; relist(); }; }
    wireCards();
  }
  render();
})();
</script></body></html>
'@

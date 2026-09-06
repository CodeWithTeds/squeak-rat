<?php

namespace Rat\Console\Commands;

use Illuminate\Console\Command;
use Rat\Support\RatBanner;

class RatUiCommand extends Command
{
    protected $signature = 'rat:ui
                            {--host=127.0.0.1 : Host to bind}
                            {--port=7331 : Port to listen}
                            {--no-open : Do not auto-open browser}
                            {--no-image}';

    protected $description = 'Start RAT UI (modern visual investigation layer).';

    public function handle(): int
    {
        $host = $this->option('host') ?: '127.0.0.1';
        $port = (int) ($this->option('port') ?: 7331);
        $noImage = (bool) $this->option('no-image');

        if (! $noImage) RatBanner::render($this->output, true, false);

        // Ensure last scan exists
        $analyzer = new \Rat\Engine\Analyzer(getcwd(), $this->loadConfig());
        $this->output->writeln('  <fg=gray>Analyzing application for UI...</>');
        $res = $analyzer->analyze();
        $this->persist($res['findings'], $res['stats'], $res['graph']);

        $url = "http://{$host}:{$port}";
        $docRoot = $this->ensureUiAssets();

        $this->output->writeln('');
        $this->output->writeln('  <fg=white;options=bold>🐀 RAT UI</>');
        $this->output->writeln('');
        $this->output->writeln('  <fg=gray>Analysis complete.</>');
        $this->output->writeln('');
        $this->output->writeln(sprintf('  <fg=white>Dashboard:</> <fg=cyan;options=underline>%s</>', $url));
        $this->output->writeln('  <fg=gray>Watching application... Press Ctrl+C to stop.</>');
        $this->output->writeln('');

        // Try to open browser
        if (! $this->option('no-open')) {
            $this->openBrowser($url);
        }

        // Serve via PHP built-in server
        $router = $docRoot . '/router.php';
        if (! file_exists($router)) {
            // fallback simple router
            file_put_contents($router, '<?php if (preg_match("/\.(?:png|js|css|json)$/", $_SERVER["REQUEST_URI"])) return false; $f = __DIR__ . "/index.html"; if (file_exists($f)) { readfile($f); } else { echo "RAT UI — missing assets. Run `npm run build` in ui/ if you modified frontend."; }');
        }

        $cmd = sprintf(
            '%s -S %s:%d -t %s %s 2>&1',
            escapeshellarg(PHP_BINARY),
            escapeshellarg($host),
            $port,
            escapeshellarg($docRoot),
            escapeshellarg($router)
        );

        $this->output->writeln(sprintf('  <fg=gray>Serving:</> <fg=white>%s</>', $docRoot));
        $this->output->writeln('  <fg=gray>' . str_repeat('─', 48) . '</>');

        // Stream server output
        $proc = popen($cmd, 'r');
        if (! $proc) {
            $this->error(' Failed to start PHP built-in server. Is port already in use?');
            return 1;
        }
        while (! feof($proc)) {
            $line = fgets($proc);
            if ($line !== false) {
                $trim = trim($line);
                if ($trim !== '') $this->output->writeln('  <fg=gray>[ui]</> ' . $trim);
            }
        }
        pclose($proc);
        return 0;
    }

    private function ensureUiAssets(): string
    {
        // Prefer built assets in resources/ui/dist, else generate a minimal self-contained UI on the fly
        $dist = dirname(__DIR__, 3) . '/resources/ui/dist';
        $fallback = getcwd() . '/.rat/ui';
        $candidates = [$dist, dirname(__DIR__, 3) . '/public/rat-ui', $fallback];

        foreach ($candidates as $c) {
            if (is_dir($c) && file_exists($c . '/index.html')) return $c;
        }

        // Generate minimal UI if missing — still professional looking
        $target = $fallback;
        if (! is_dir($target)) @mkdir($target, 0755, true);
        if (! file_exists($target . '/index.html')) {
            @file_put_contents($target . '/index.html', $this->minimalUiHtml());
        }
        // Ensure data endpoint can serve last.json — router.php will handle /api
        if (! file_exists($target . '/router.php')) {
            @file_put_contents($target . '/router.php', $this->routerPhp());
        }
        return $target;
    }

    private function minimalUiHtml(): string
    {
        // Self-contained, dark-first, information-dense UI with graph via lightweight D3-like canvas
        // Uses Tailwind CDN + vanilla JS fetching /.rat.last.json
        return <<<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>🐀 RAT — Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root { color-scheme: dark; }
  body { background:#0b0c0f; color:#e5e7eb; font-family: ui-monospace, "Cascadia Code", Menlo, monospace; }
  .card { background:#121418; border:1px solid #1f2430; }
  .sev-critical{ color:#ef4444 } .sev-high{ color:#f59e0b } .sev-medium{ color:#06b6d4 } .sev-low{ color:#3b82f6 }
</style>
</head>
<body class="min-h-screen">
<header class="border-b border-[#1f2430] sticky top-0 bg-[#0b0c0f]/90 backdrop-blur z-10">
  <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <span class="text-2xl">🐀</span>
      <div>
        <div class="font-bold tracking-widest">RAT <span class="text-[#ef4444]">—</span> <span class="text-gray-400 font-normal">Laravel Security & Behavior</span></div>
        <div class="text-xs text-gray-500">RAT follows the trail. • <span id="projectRoot" class="text-gray-400">—</span></div>
      </div>
    </div>
    <div class="flex items-center gap-2">
      <span class="text-xs px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">Terminal-first</span>
      <button onclick="refresh()" class="text-xs px-3 py-1.5 rounded bg-white text-black font-bold hover:bg-gray-200">↻ Refresh analysis</button>
    </div>
  </div>
</header>

<main class="max-w-7xl mx-auto px-6 py-6 grid grid-cols-12 gap-6">
  <!-- Left: Health -->
  <section class="col-span-12 lg:col-span-4 space-y-6">
    <div class="card rounded-xl p-5">
      <div class="text-xs tracking-widest text-gray-500 mb-3">APPLICATION HEALTH</div>
      <div class="grid grid-cols-3 gap-4 text-center">
        <div><div id="healthScore" class="text-3xl font-black">—</div><div class="text-[10px] tracking-widest text-gray-500">SCORE</div></div>
        <div><div id="highCount" class="text-3xl font-black text-amber-400">—</div><div class="text-[10px] tracking-widest text-gray-500">HIGH</div></div>
        <div><div id="medCount" class="text-3xl font-black text-cyan-400">—</div><div class="text-[10px] tracking-widest text-gray-500">MEDIUM</div></div>
      </div>
      <div class="mt-4 h-px bg-[#1f2430]"></div>
      <div id="sevBreakdown" class="mt-4 space-y-1 text-sm"></div>
    </div>

    <div class="card rounded-xl p-5">
      <div class="text-xs tracking-widest text-gray-500 mb-3">ATTACK SURFACE</div>
      <div id="surface" class="space-y-2 text-sm"></div>
    </div>

    <div class="card rounded-xl p-5">
      <div class="text-xs tracking-widest text-gray-500 mb-2">FLOWS</div>
      <div class="text-xs text-gray-500 mb-2">Click a route to trace →</div>
      <div id="routeList" class="space-y-1 max-h-[320px] overflow-auto pr-1"></div>
    </div>
  </section>

  <!-- Center: Findings -->
  <section class="col-span-12 lg:col-span-5 space-y-6">
    <div class="card rounded-xl p-5">
      <div class="flex items-center justify-between mb-3">
        <div class="text-xs tracking-widest text-gray-500">FINDINGS EXPLORER</div>
        <div class="flex gap-1">
          <button data-filter="all" class="filter-btn text-[11px] px-2 py-1 rounded bg-white text-black font-bold">All</button>
          <button data-filter="critical" class="filter-btn text-[11px] px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">Critical</button>
          <button data-filter="high" class="filter-btn text-[11px] px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">High</button>
          <button data-filter="medium" class="filter-btn text-[11px] px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">Medium</button>
          <button data-filter="low" class="filter-btn text-[11px] px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">Low</button>
        </div>
      </div>
      <input id="search" placeholder="Search findings, entry, sink..." class="w-full text-xs px-3 py-2 rounded bg-[#0b0c0f] border border-[#232836] outline-none mb-3"/>
      <div id="findingsList" class="space-y-3 max-h-[560px] overflow-auto pr-1"></div>
    </div>
  </section>

  <!-- Right: Graph / Detail -->
  <section class="col-span-12 lg:col-span-3 space-y-6">
    <div class="card rounded-xl p-5">
      <div class="text-xs tracking-widest text-gray-500 mb-3">APPLICATION GRAPH</div>
      <canvas id="graphCanvas" width="360" height="320" class="w-full rounded bg-[#0b0c0f] border border-[#1f2430]"></canvas>
      <div class="mt-2 flex flex-wrap gap-1 text-[10px]">
        <span class="px-1.5 py-0.5 rounded bg-[#1a1d24] border border-[#232836]">Routes</span>
        <span class="px-1.5 py-0.5 rounded bg-[#1a1d24] border border-[#232836]">Controllers</span>
        <span class="px-1.5 py-0.5 rounded bg-[#1a1d24] border border-[#232836]">Services</span>
        <span class="px-1.5 py-0.5 rounded bg-[#1a1d24] border border-[#232836]">Models</span>
        <span class="px-1.5 py-0.5 rounded bg-[#1a1d24] border border-[#232836]">Jobs</span>
      </div>
      <div id="graphDetail" class="mt-3 text-xs text-gray-400 min-h-[60px]">Click a node in the list or canvas.</div>
    </div>

    <div id="detailPanel" class="card rounded-xl p-5 hidden"></div>
  </section>
</main>

<footer class="max-w-7xl mx-auto px-6 pb-8 text-[11px] text-gray-600">
  RAT engine is the brain • Terminal is the control center • UI is the microscope • <span class="text-gray-400">RAT follows the trail. 🐀</span>
</footer>

<script>
let DATA=null, FILTER='all';
async function load(){
  // Try multiple endpoints
  const urls=['/api/data','/.rat.last.json','/storage/rat/last.json','/.rat/last.json'];
  for(const u of urls){
    try{
      const r=await fetch(u); if(!r.ok) continue; const j=await r.json();
      if(j.findings || j.graph){ DATA=j; break; }
      if(j.stats) { DATA=j; break; }
    }catch(e){}
  }
  // Fallback: try relative last.json served by router
  if(!DATA){
    try{ const r=await fetch('/last.json'); if(r.ok) DATA=await r.json(); }catch(e){}
  }
  if(!DATA){ document.getElementById('findingsList').innerHTML='<div class="text-xs text-red-400">No data. Run <code>php artisan rat:scan</code> first.</div>'; return; }
  render();
}
function render(){
  const stats=DATA.stats||{};
  const findings=DATA.findings||[];
  const graph=DATA.graph||{nodes:[],edges:[]};
  document.getElementById('projectRoot').textContent=stats.project_root||location.hostname;
  const counts=stats.findings||countsFrom(findings);
  document.getElementById('highCount').textContent=counts.high||0;
  document.getElementById('medCount').textContent=counts.medium||0;
  const score=Math.max(0,100 - (counts.critical*25 + counts.high*12 + counts.medium*6 + counts.low*2));
  document.getElementById('healthScore').textContent=score;
  document.getElementById('healthScore').className='text-3xl font-black '+(score>80?'text-emerald-400':score>60?'text-yellow-400':'text-red-400');
  document.getElementById('sevBreakdown').innerHTML=`
    <div class="flex justify-between"><span class="text-gray-500">Critical</span><span class="sev-critical font-bold">${counts.critical||0}</span></div>
    <div class="flex justify-between"><span class="text-gray-500">High</span><span class="sev-high font-bold">${counts.high||0}</span></div>
    <div class="flex justify-between"><span class="text-gray-500">Medium</span><span class="sev-medium font-bold">${counts.medium||0}</span></div>
    <div class="flex justify-between"><span class="text-gray-500">Low</span><span class="text-blue-400 font-bold">${counts.low||0}</span></div>
  `;
  document.getElementById('surface').innerHTML=Object.entries(stats.by_type||graph.by_type||{}).map(([k,v])=>`<div class="flex justify-between"><span class="text-gray-500">${k}</span><span class="font-bold">${v}</span></div>`).join('') || '<span class="text-gray-600">—</span>';

  // routes
  const routeNodes=(graph.nodes||[]).filter(n=>n.type==='Route').slice(0,40);
  document.getElementById('routeList').innerHTML=routeNodes.map(n=>`<button onclick="showFlow('${n.name.replace(/'/g,"\\'")}')" class="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-[#1a1d24] border border-transparent hover:border-[#232836]"><span class="text-cyan-400">${esc(n.name)}</span> <span class="text-gray-600 text-[10px]">${esc(n.file||'')}</span></button>`).join('') || '<span class="text-xs text-gray-600">No routes</span>';

  renderFindings(findings);
  drawGraph(graph);
}
function countsFrom(findings){
  const c={critical:0,high:0,medium:0,low:0,info:0};
  findings.forEach(f=>{ const k=(f.severity||'info').toLowerCase(); c[k]=(c[k]||0)+1; });
  return c;
}
function renderFindings(findings){
  const q=(document.getElementById('search').value||'').toLowerCase();
  let list=findings.filter(f=>{
    if(FILTER!=='all' && (f.severity||'').toLowerCase()!==FILTER) return false;
    if(q && ![f.id,f.title,f.entry,f.sink,f.source].join(' ').toLowerCase().includes(q)) return false;
    return true;
  });
  document.getElementById('findingsList').innerHTML=list.map(f=>`
    <div onclick="openFinding('${f.id}')" class="p-3 rounded border border-[#1f2430] bg-[#0b0c0f] hover:border-[#2a3142] cursor-pointer">
      <div class="flex items-center gap-2"><span class="text-[10px] px-1.5 py-0.5 rounded font-bold ${sevClass(f.severity)}">${(f.severity||'').toUpperCase()}</span><span class="text-xs font-bold">${esc(f.id)}</span><span class="ml-auto text-[10px] text-gray-500">conf ${esc((f.confidence||'').toUpperCase())}</span></div>
      <div class="text-xs mt-1">${esc(f.title)}</div>
      <div class="text-[11px] text-gray-500">${esc(f.entry||'')} → ${esc(f.sink||'')}</div>
    </div>
  `).join('') || '<div class="text-xs text-gray-500">No findings for filter.</div>';
}
function sevClass(s){ s=(s||'').toLowerCase(); if(s==='critical') return 'bg-red-500 text-black'; if(s==='high') return 'bg-amber-400 text-black'; if(s==='medium') return 'bg-cyan-400 text-black'; if(s==='low') return 'bg-blue-500 text-white'; return 'bg-gray-700 text-white'; }
function esc(s){ return (s||'').replace(/[&<>"']/g,c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }
function openFinding(id){
  const f=(DATA.findings||[]).find(x=>x.id===id); if(!f) return;
  const panel=document.getElementById('detailPanel');
  panel.classList.remove('hidden');
  panel.innerHTML=`
    <div class="text-xs tracking-widest text-gray-500">${esc(f.id)} • ${esc((f.severity||'').toUpperCase())} • conf ${esc((f.confidence||'').toUpperCase())}</div>
    <div class="font-bold mt-1">${esc(f.title)}</div>
    <div class="text-xs text-gray-400 mt-1">${esc(f.description||'')}</div>
    <div class="mt-3 text-xs"><div class="text-gray-500">ENTRY</div><div class="text-cyan-400">${esc(f.entry)}</div></div>
    <div class="mt-2 text-xs"><div class="text-gray-500">SOURCE → SINK</div><div class="text-yellow-400">${esc(f.source)}</div><div class="text-gray-600">↓</div><div class="text-red-400">${esc(f.sink)}</div></div>
    <div class="mt-3"><div class="text-xs text-gray-500">FLOW</div><div class="mt-1 space-y-1">${(f.flow||[]).map((n,i)=>`<div class="text-xs flex items-center gap-2"><span class="w-6 h-6 grid place-items-center rounded bg-[#1a1d24] border border-[#232836] text-[10px]">${i+1}</span><span>${esc(n)}</span></div>`).join('')}</div></div>
    <div class="mt-3 text-xs text-gray-400">${esc(f.why||'')}</div>
    <div class="mt-3 text-xs"><div class="text-gray-500">RECOMMENDATIONS</div><ul class="list-disc pl-4 mt-1 space-y-1">${(f.recommendations||[]).map(r=>`<li>${esc(r)}</li>`).join('')}</ul></div>
    <div class="mt-3 text-xs text-gray-500">${esc(f.file||'')}${f.line?':'+f.line:''}</div>
    <div class="mt-3 flex gap-2"><button onclick="showWhy('${esc(f.flow?.[1]||'')}')" class="text-xs px-2 py-1 rounded bg-white text-black font-bold">Why?</button><button onclick="showFlow('${esc(f.entry)}')" class="text-xs px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">Flow</button></div>
  `;
  panel.scrollIntoView({behavior:'smooth'});
}
function showFlow(route){ alert('Flow visualizer for: '+route+'\n\nIn full UI, this renders an interactive trace.\nTip: run `php artisan rat:flow \"'+route+'\"` in terminal for ASCII trace.'); }
function showWhy(target){ alert('Why? investigation for: '+target+'\n\nRun `php artisan rat:why '+target+'` in terminal for full dependency trail.'); }
function drawGraph(graph){
  const c=document.getElementById('graphCanvas'), ctx=c.getContext('2d');
  const nodes=graph.nodes||[], edges=graph.edges||[];
  ctx.clearRect(0,0,c.width,c.height);
  if(nodes.length===0){ ctx.fillStyle='#6b7280'; ctx.font='11px monospace'; ctx.fillText('No graph data — run rat:scan', 20,160); return; }
  // Simple force-ish layout: group by type
  const types=[...new Set(nodes.map(n=>n.type))];
  const typeX={}; types.forEach((t,i)=> typeX[t]=40 + i*( (c.width-80) / Math.max(1,types.length-1)) );
  const byType={}; nodes.forEach(n=> (byType[n.type]=byType[n.type]||[]).push(n));
  const pos={};
  Object.entries(byType).forEach(([t, arr])=>{
    const x=typeX[t];
    arr.forEach((n,i)=>{
      const y=30 + (i+1)*( (c.height-60) / (arr.length+1));
      pos[n.id]={x: x + (Math.random()-0.5)*12, y};
    });
  });
  // edges
  ctx.strokeStyle='#232836'; ctx.lineWidth=1;
  edges.forEach(e=>{
    const a=pos[e.from], b=pos[e.to]; if(!a||!b) return;
    ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
    // arrow
    const ang=Math.atan2(b.y-a.y,b.x-a.x);
    ctx.save(); ctx.translate(b.x,b.y); ctx.rotate(ang);
    ctx.fillStyle='#2a3142'; ctx.beginPath(); ctx.moveTo(0,0); ctx.lineTo(-6,-3); ctx.lineTo(-6,3); ctx.closePath(); ctx.fill();
    ctx.restore();
  });
  // nodes
  nodes.forEach(n=>{
    const p=pos[n.id]; if(!p) return;
    const col= n.type==='Route'?'#06b6d4': n.type==='Controller'?'#f59e0b': n.type==='Service'?'#a78bfa': n.type==='Model'?'#22c55e': n.type==='Job'?'#ec4899': n.type==='External'?'#facc15':'#e5e7eb';
    ctx.fillStyle=col; ctx.beginPath(); ctx.arc(p.x,p.y,6,0,Math.PI*2); ctx.fill();
    ctx.fillStyle='#e5e7eb'; ctx.font='8px monospace'; ctx.fillText(n.name.slice(0,10), p.x+8, p.y+3);
  });
  c.onclick=(e)=>{
    const r=c.getBoundingClientRect(); const x=(e.clientX-r.left)*(c.width/r.width), y=(e.clientY-r.top)*(c.height/r.height);
    let best=null, bestD=Infinity;
    Object.entries(pos).forEach(([id,p])=>{ const d=Math.hypot(p.x-x,p.y-y); if(d<12 && d<bestD){ bestD=d; best=nodes.find(n=>n.id===id); } });
    if(best){
      const incom=(graph.edges||[]).filter(ed=>ed.to===best.id).length;
      const outg=(graph.edges||[]).filter(ed=>ed.from===best.id).length;
      document.getElementById('graphDetail').innerHTML=`<div class="font-bold text-white">${esc(best.name)} <span class="text-gray-500">${esc(best.type)}</span></div><div class="text-gray-500">${esc(best.file||'')}</div><div class="mt-2 text-gray-400">Incoming: ${incom} • Outgoing: ${outg}</div><div class="mt-2 flex gap-2"><button onclick="showWhy('${esc(best.name)}')" class="text-[11px] px-2 py-1 rounded bg-white text-black font-bold">Why?</button><button onclick="showFlow('${esc(best.name)}')" class="text-[11px] px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]">Flow</button></div>`;
    }
  };
}
document.getElementById('search').addEventListener('input',()=> renderFindings(DATA.findings||[]));
document.querySelectorAll('.filter-btn').forEach(b=> b.addEventListener('click',()=>{
  document.querySelectorAll('.filter-btn').forEach(x=> x.className='filter-btn text-[11px] px-2 py-1 rounded bg-[#1a1d24] border border-[#232836]');
  b.className='filter-btn text-[11px] px-2 py-1 rounded bg-white text-black font-bold';
  FILTER=b.dataset.filter; renderFindings(DATA.findings||[]);
}));
function refresh(){ fetch('/api/refresh',{method:'POST'}).then(()=> location.reload()).catch(()=> location.reload()); }
load();
</script>
</body>
</html>
HTML;
    }

    private function routerPhp(): string
    {
        return <<<'PHP'
<?php
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$root = __DIR__;
$cwd = dirname(__DIR__, 3); // .rat/ui -> .rat -> cwd
if ($uri === '/api/data' || $uri === '/api/graph' || $uri === '/last.json') {
    $candidates = [$cwd.'/.rat.last.json', $cwd.'/storage/rat/last.json', $cwd.'/.rat/last.json', $root.'/last.json'];
    foreach ($candidates as $p) {
        if (file_exists($p)) {
            header('Content-Type: application/json');
            header('Access-Control-Allow-Origin: *');
            readfile($p);
            exit;
        }
    }
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['error'=>'no scan data','hint'=>'run php artisan rat:scan']);
    exit;
}
if ($uri === '/api/refresh' && $_SERVER['REQUEST_METHOD']==='POST') {
    // Trigger re-scan via Analyzer if available
    $autoload = $cwd.'/vendor/autoload.php';
    if (file_exists($autoload)) require $autoload;
    $altAutoload = dirname(__DIR__,2).'/vendor/autoload.php';
    if (file_exists($altAutoload)) require $altAutoload;
    try {
        $analyzer = new \Rat\Engine\Analyzer($cwd, []);
        $res = $analyzer->analyze();
        $payload = ['generated_at'=>date('c'),'stats'=>$res['stats'],'findings'=>array_map(fn($f)=>$f->toArray(), $res['findings']),'graph'=>$res['graph']->toArray()];
        file_put_contents($cwd.'/.rat.last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        if (!is_dir($cwd.'/storage/rat')) @mkdir($cwd.'/storage/rat',0755,true);
        file_put_contents($cwd.'/storage/rat/last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        header('Content-Type: application/json');
        echo json_encode(['ok'=>true,'findings'=>count($payload['findings'])]);
        exit;
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['error'=>$e->getMessage()]);
        exit;
    }
}
if (preg_match('/\.(?:png|js|css|json|svg|ico)$/', $uri)) return false;
$file = $root . '/index.html';
if (file_exists($file)) { readfile($file); exit; }
http_response_code(404);
echo "RAT UI — not found";
PHP;
    }

    private function openBrowser(string $url): void
    {
        $os = PHP_OS_FAMILY;
        $cmd = null;
        if ($os === 'Darwin') $cmd = sprintf('open %s >/dev/null 2>&1 &', escapeshellarg($url));
        elseif ($os === 'Windows') $cmd = sprintf('start "" %s', escapeshellarg($url));
        else $cmd = sprintf('xdg-open %s >/dev/null 2>&1 &', escapeshellarg($url));
        if ($cmd) @exec($cmd);
    }

    private function persist(array $findings, array $stats, $graph): void
    {
        $payload = ['generated_at'=>date('c'),'stats'=>$stats,'findings'=>array_map(fn($f)=>$f->toArray(), $findings),'graph'=>$graph->toArray()];
        @file_put_contents(getcwd().'/.rat.last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        if (! is_dir(getcwd().'/storage/rat')) @mkdir(getcwd().'/storage/rat',0755,true);
        @file_put_contents(getcwd().'/storage/rat/last.json', json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
        $fallback = getcwd().'/.rat/ui/last.json';
        if (is_dir(dirname($fallback))) @file_put_contents($fallback, json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
    }

    private function loadConfig(): array
    {
        $p=getcwd().'/config/rat.php'; if(file_exists($p)){try{$c=require $p; if(is_array($c)) return $c;}catch(\Throwable $e){}} return [];
    }
}

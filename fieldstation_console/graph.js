/* Issue-local evidence plus the direct relations returned for each loaded item. */
let graphState=null;
function graphStatus(e){if(e?.lifecycle_status==='void')return 'void';return ['usable','questionable','unusable_for_purpose'].includes(e?.quality_status)?e.quality_status:'unknown'}
const graphLegend={usable:'可用',questionable:'存疑',unusable_for_purpose:'不适用于目的',unknown:'未知 / 未读取',void:'已作废'};
function graphLoadForEvidence(){
  const state=imState, gen=imGeneration;
  if(!graphState||graphState.owner!==state||graphState.issue!==state.selected)graphState={owner:state,issue:state.selected,nodes:{},pages:{},edges:{},restricted:0};
  let g=graphState;
  for(const x of state.evidence){if(x.evidence_id&&!x.restricted)g.nodes[x.evidence_id]={...(g.nodes[x.evidence_id]||{}),...x};}
  graphDraw();
  const ids=state.evidence.filter(x=>x.evidence_id&&!x.restricted&&!g.pages[x.evidence_id]).map(x=>x.evidence_id);
  for(const id of ids)g.pages[id]={loading:true};
  graphDraw();
  let next=0; async function worker(){while(next<ids.length){let id=ids[next++];await graphFetch(id,false,g,gen)}}
  Promise.all(Array.from({length:Math.min(4,ids.length)},worker));
}
async function graphFetch(id,more,g,gen){
  let p=g.pages[id];if(!p)return;p.loading=true;p.error='';graphDraw();
  try{let d=await imRead('neighbors',id,more?p.next:'',more?p.snapshot:'');if(graphState!==g||gen!==imGeneration)return;
    for(const r of d.items||[]){if(r.restricted){g.restricted++;continue}let a=r.source_evidence_id,b=r.target_evidence_id;if(!a||!b)continue;g.nodes[a] ||= {evidence_id:a};g.nodes[b] ||= {evidence_id:b};let key=r.layer+'|'+(r.relation_id||[a,b,r.relation_type,JSON.stringify(r)].join('|'));g.edges[key]=r}
    p.next=d.next_cursor||'';p.snapshot=d.snapshot||'';p.loaded=true;
  }catch(e){if(graphState===g&&gen===imGeneration)p.error=e.message}
  finally{if(graphState===g&&gen===imGeneration){p.loading=false;graphDraw()}}
}
function graphSelect(id){if(!graphState||!graphState.nodes[id])return;imState.focus=id;imRenderEvidence();graphDraw();let target=$('#graphDetail');if(!target)return;target.innerHTML='<div class="im-load">正在读取材料详情…</div>';let g=graphState,gen=imGeneration;imRead('detail',id).then(d=>{if(graphState!==g||gen!==imGeneration||imState.focus!==id)return;let e=d.evidence||d;g.nodes[id]={...g.nodes[id],...e};e=g.nodes[id];graphDraw();target=$('#graphDetail');target.innerHTML=`<div class="graph-detail-title">${esc(e.short_description||id)}</div><div class="im-muted">${esc(id)} · 质量状态：${esc(graphLegend[graphStatus(e)])} · 生命周期：${esc(e.lifecycle_status||'未提供')}</div><details open><summary class="raw-toggle">材料详情</summary><pre class="im-raw">${esc(JSON.stringify(e,null,2))}</pre></details>`}).catch(e=>{if(graphState===g&&gen===imGeneration&&imState.focus===id&&$('#graphDetail'))$('#graphDetail').innerHTML=`<div class="im-error">详情读取失败：${esc(e.message)}</div>`})}
function graphDraw(){
  let out=$('#imRelations'),g=graphState;if(!out||!g||g.owner!==imState||g.issue!==imState.selected)return;
  let ids=Object.keys(g.nodes).sort(),edges=Object.values(g.edges),pages=Object.entries(g.pages),loading=pages.filter(([,p])=>p.loading).length,errors=pages.filter(([,p])=>p.error),more=pages.filter(([,p])=>p.next),restricted=g.restricted;
  if(!ids.length){out.className='';out.innerHTML='<div class="im-placeholder">此 Issue 没有可绘制的可见材料。</div>';return}
  // Deterministic concentric rings avoid node overlap without assuming acyclicity.
  let rings=[],remaining=ids.length,cap=8;while(remaining>0){let n=Math.min(cap,remaining);rings.push(n);remaining-=n;cap+=8}
  let radius=Math.max(230, rings.length*200+100),size=radius*2+180,center=size/2,pos={},idx=0;
  for(let r=0;r<rings.length;r++){let ring=rings[r],dist=(r+1)*200;for(let j=0;j<ring;j++){let angle=2*Math.PI*j/ring-Math.PI/2;pos[ids[idx++]]={x:center+Math.cos(angle)*dist,y:center+Math.sin(angle)*dist}}}
  let paths=edges.map((e,i)=>{let a=pos[e.source_evidence_id],b=pos[e.target_evidence_id];if(!a||!b)return '';let dx=b.x-a.x,dy=b.y-a.y,len=Math.hypot(dx,dy)||1;let ux=dx/len,uy=dy/len,x1=a.x+ux*67,y1=a.y+uy*27,x2=b.x-ux*67,y2=b.y-uy*27;let bend=((i%3)-1)*22, mx=(x1+x2)/2-uy*bend,my=(y1+y2)/2+ux*bend;if(e.source_evidence_id===e.target_evidence_id){return `<path d="M ${a.x+35} ${a.y-22} C ${a.x+110} ${a.y-110}, ${a.x-110} ${a.y-110}, ${a.x-35} ${a.y-22}" class="graph-edge" marker-end="url(#arrow)"><title>${esc(imLabel(e.relation_type))}</title></path>`}return `<path d="M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}" class="graph-edge" marker-end="url(#arrow)"><title>${esc(e.source_evidence_id+' '+imLabel(e.relation_type)+' '+e.target_evidence_id)}</title></path><text x="${mx}" y="${my-4}" class="graph-edge-label">${esc(imLabel(e.relation_type||e.kind))}</text>`}).join('');
  let nodes=ids.map(id=>{let n=g.nodes[id],p=pos[id],title=n.short_description||id,status=graphStatus(n);return `<button class="graph-node ${status} ${imState.focus===id?'selected':''}" style="left:${p.x-67}px;top:${p.y-27}px" data-node="${esc(id)}" title="${esc(title+' · '+graphLegend[status])}" aria-label="${esc(title+'，'+graphLegend[status])}"><span>${esc(title)}</span></button>`}).join('');
  let notice=[imState.evNext?'材料列表还有后续页':null,loading?`正在读取 ${loading} 项关系`:null,more.length?`${more.length} 项关系还有后续页`:null,errors.length?`${errors.length} 项关系读取失败`:null,restricted?'存在受限关系记录':null].filter(Boolean).join(' · ');
  let previousScroll=out.querySelector('.graph-scroll'),scrollLeft=previousScroll?.scrollLeft,scrollTop=previousScroll?.scrollTop,previousDetail=out.querySelector('#graphDetail')?.innerHTML||'';out.className='';out.innerHTML=`<div class="graph-legend">${Object.entries(graphLegend).map(([k,v])=>`<span><i class="legend-dot ${k}"></i>${v}</span>`).join('')}</div><p class="im-muted">图含已加载材料及其直接关系；图外材料可能以 ID 和未知状态显示。拖动滚动条浏览，点击节点查看详情。</p><div class="graph-notice">${esc(notice||'已读取已加载材料的关系页')}</div><div class="graph-scroll" tabindex="0" aria-label="Evidence 关系图，可滚动"><div class="graph-canvas" style="width:${size}px;height:${size}px"><svg width="${size}" height="${size}" aria-hidden="true"><defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#91a698"/></marker></defs>${paths}</svg>${nodes}</div></div><div id="graphDetail" class="graph-detail"></div>`;
  if(previousScroll){out.querySelector('.graph-scroll').scrollLeft=scrollLeft;out.querySelector('.graph-scroll').scrollTop=scrollTop}else{let viewport=out.querySelector('.graph-scroll');viewport.scrollLeft=Math.max(0,(size-viewport.clientWidth)/2);viewport.scrollTop=Math.max(0,(size-viewport.clientHeight)/2)}$('#graphDetail').innerHTML=previousDetail;out.querySelectorAll('[data-node]').forEach(b=>b.onclick=()=>graphSelect(b.dataset.node));
  let holder=$('#imRelMore');holder.innerHTML=more.length?'<button class="btn im-more" id="graphMore">加载后续关系页</button>':'';if(more.length)$('#graphMore').onclick=()=>{for(const [id] of more)graphFetch(id,true,g,imGeneration)};
  if(errors.length){let button=document.createElement('button');button.className='btn im-more';button.textContent='重试失败的关系';button.onclick=()=>{for(const [id,p] of errors)graphFetch(id,!!p.next,g,imGeneration)};holder.append(button)}
}

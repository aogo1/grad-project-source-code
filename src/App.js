import { useState, useEffect, useCallback } from "react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Shield, Activity, AlertTriangle, Target, Cpu, Eye, Search, Bot, Loader, ChevronRight, FileText, ListChecks } from "lucide-react";

const BACKEND = "http://172.20.10.6:4000";

const TACTIC_CLR = {
  "Credential Access":"#ff4d6a","Execution":"#ff8c42","Command and Control":"#c44dff",
  "Reconnaissance":"#4dc9ff","Persistence":"#ffd84d","Defense Evasion":"#8cff4d",
  "Lateral Movement":"#ff4dc4","Discovery":"#4dff88",
};
const rC = s => s>=70?"#ff2d55":s>=50?"#ff8c42":s>=30?"#ffd84d":"#4dff88";
const sC = s => s>=13?"#ff2d55":s>=10?"#ff8c42":s>=7?"#ffd84d":"#4dff88";

function useAIAnalysis(){
  const [loading,setLoading]=useState(false);
  const [result,setResult]=useState(null);
  const [error,setError]=useState(null);
  const analyze=useCallback(async(alert)=>{
    setLoading(true);setError(null);setResult(null);
    try{
      const res=await fetch("https://api.anthropic.com/v1/messages",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          model:"claude-sonnet-4-6",max_tokens:1000,
          messages:[{role:"user",content:`You are a senior SOC analyst. Analyze this security alert.\nALERT:\n- Rule: ${alert.rule_id} — ${alert.desc}\n- MITRE: ${alert.mitre} / ${alert.tactic}\n- Agent: ${alert.agent} (${alert.agentIp})\n- Risk Score: ${alert.score}/100\n- ML Confidence: ${(alert.mlConf*100).toFixed(1)}%\n- Wazuh=${alert.scores.wazuh}, ML=${alert.scores.ml}, AbuseIPDB=${alert.scores.abuse}, VirusTotal=${alert.scores.vt}\n- Action: ${alert.action}\nRespond ONLY with valid JSON (no markdown):\n{"threat_summary":"...","mitre_explanation":"...","risk_assessment":"...","immediate_actions":["..."],"ioc_indicators":["..."],"false_positive_likelihood":"..."}`}]
        })
      });
      const data=await res.json();
      const text=data.content[0].text.replace(/\`\`\`json|\`\`\`/g,"").trim();
      setResult(JSON.parse(text));
    }catch(e){setError(e.message);}
    setLoading(false);
  },[]);
  return{analyze,loading,result,error,clear:()=>{setResult(null);setError(null);}};
}

const Tt=({active,payload,label})=>{
  if(!active||!payload?.length)return null;
  return(<div style={{background:"#141926",border:"1px solid rgba(255,255,255,0.1)",borderRadius:8,padding:"8px 12px",fontSize:12}}>
    <div style={{color:"#8892a4",marginBottom:4}}>{label}</div>
    {payload.map((p,i)=><div key={i} style={{color:p.color}}>{p.name}: {p.value}</div>)}
  </div>);
};

function Badge({color,children}){
  return <span style={{display:"inline-block",padding:"2px 8px",borderRadius:4,fontSize:11,fontWeight:600,background:`${color}18`,color,border:`1px solid ${color}25`}}>{children}</span>;
}

function ScoreBar({label,value,weight,color}){
  return(<div style={{marginBottom:10}}>
    <div style={{display:"flex",justifyContent:"space-between",fontSize:11,marginBottom:4}}>
      <span style={{color:"#8892a4"}}>{label} <span style={{opacity:0.5}}>({weight})</span></span>
      <span style={{color,fontFamily:"monospace",fontWeight:600}}>{value}</span>
    </div>
    <div style={{height:6,background:"rgba(255,255,255,0.06)",borderRadius:3}}>
      <div style={{height:6,borderRadius:3,background:color,width:`${Math.min(value,100)}%`,transition:"width 0.6s ease"}}/>
    </div>
  </div>);
}

function ConnStatus({connected}){
  return(<div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,color:connected?"#4dff88":"#ff4d6a"}}>
    <div style={{width:8,height:8,borderRadius:"50%",background:connected?"#4dff88":"#ff4d6a",boxShadow:connected?"0 0 6px #4dff88":"none"}}/>
    {connected?"Live — connected to VM2":"Disconnected from backend"}
  </div>);
}

export default function Dashboard(){
  const [alerts,setAlerts]=useState([]);
  const [view,setView]=useState("dashboard");
  const [selected,setSelected]=useState(null);
  const [filter,setFilter]=useState("all");
  const [search,setSearch]=useState("");
  const [tab,setTab]=useState("overview");
  const [connected,setConnected]=useState(false);
  const [lastFetch,setLastFetch]=useState(null);
  const ai=useAIAnalysis();

  useEffect(()=>{
    const fetchAlerts=async()=>{
      try{
        const res=await fetch(`${BACKEND}/alerts`);
        if(!res.ok)throw new Error("err");
        const data=await res.json();
        setAlerts(data);setConnected(true);
        setLastFetch(new Date().toLocaleTimeString("en-GB"));
      }catch(e){setConnected(false);}
    };
    fetchAlerts();
    const iv=setInterval(fetchAlerts,5000);
    return()=>clearInterval(iv);
  },[]);

  const filtered=alerts.filter(a=>{
    if(filter==="critical"&&a.score<70)return false;
    if(filter==="high"&&(a.score<50||a.score>=70))return false;
    if(filter==="medium"&&(a.score<30||a.score>=50))return false;
    if(filter==="low"&&a.score>=30)return false;
    if(search&&!`${a.desc} ${a.mitre} ${a.agent} ${a.rule_id}`.toLowerCase().includes(search.toLowerCase()))return false;
    return true;
  });

  const total=alerts.length;
  const critical=alerts.filter(a=>a.score>=70).length;
  const cases=alerts.filter(a=>a.action!=="log_only").length;
  const autoResp=alerts.filter(a=>a.action==="auto_response").length;
  const avgScore=total?Math.round(alerts.reduce((s,a)=>s+a.score,0)/total):0;
  const avgML=total?(alerts.reduce((s,a)=>s+a.mlConf,0)/total).toFixed(2):"0.00";

  const hours={};
  alerts.forEach(a=>{const h=new Date(a.time).getHours();const k=`${String(h).padStart(2,"0")}:00`;hours[k]=(hours[k]||0)+1;});
  const timeData=Object.entries(hours).sort(([a],[b])=>a.localeCompare(b)).map(([hour,count])=>({hour,alerts:count}));

  const tacCounts={};
  alerts.forEach(a=>{tacCounts[a.tactic]=(tacCounts[a.tactic]||0)+1;});
  const tacData=Object.entries(tacCounts).map(([name,value])=>({name:name.length>16?name.slice(0,14)+"…":name,full:name,value})).sort((a,b)=>b.value-a.value);

  const sevBuckets=[
    {name:"Critical",count:alerts.filter(a=>a.score>=70).length,color:"#ff2d55"},
    {name:"High",count:alerts.filter(a=>a.score>=50&&a.score<70).length,color:"#ff8c42"},
    {name:"Medium",count:alerts.filter(a=>a.score>=30&&a.score<50).length,color:"#ffd84d"},
    {name:"Low",count:alerts.filter(a=>a.score<30).length,color:"#4dff88"},
  ];

  const panel={background:"rgba(255,255,255,0.025)",border:"1px solid rgba(255,255,255,0.05)",borderRadius:12,padding:20};
  const pt={fontSize:12,fontWeight:600,color:"#8892a4",textTransform:"uppercase",letterSpacing:1,marginBottom:14,display:"flex",alignItems:"center",gap:8};

  const openAlert=(a)=>{setSelected(a);setView("detail");setTab("overview");ai.clear();};
  const closeAlert=()=>{setView("dashboard");setSelected(null);ai.clear();};

  if(view==="detail"&&selected){
    return(
      <div style={{background:"#0b0f19",color:"#e8ecf4",fontFamily:"Arial,sans-serif",minHeight:"100vh"}}>
        <div style={{padding:"16px 24px",borderBottom:"1px solid rgba(255,255,255,0.06)",display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <button onClick={closeAlert} style={{background:"rgba(255,255,255,0.05)",border:"1px solid rgba(255,255,255,0.08)",borderRadius:8,padding:"6px 14px",color:"#8892a4",cursor:"pointer",fontSize:12}}>← Back</button>
            <Shield size={18} color="#00d4ff"/>
            <span style={{fontWeight:600}}>Case #{selected.id}</span>
            <Badge color={rC(selected.score)}>{selected.score>=70?"CRITICAL":selected.score>=50?"HIGH":selected.score>=30?"MEDIUM":"LOW"}</Badge>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <Badge color={TACTIC_CLR[selected.tactic]||"#4dc9ff"}>{selected.mitre}</Badge>
            <span style={{fontSize:11,color:"#8892a4",fontFamily:"monospace"}}>{new Date(selected.time).toLocaleTimeString("en-GB")}</span>
          </div>
        </div>
        <div style={{padding:"20px 24px",display:"flex",flexDirection:"column",gap:20}}>
          <div style={{...panel,display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:20}}>
            <div style={{flex:1,minWidth:280}}>
              <div style={{fontSize:20,fontWeight:700,marginBottom:8}}>{selected.desc}</div>
              <div style={{fontSize:13,color:"#8892a4",lineHeight:1.9}}>
                Rule <span style={{color:"#e8ecf4",fontFamily:"monospace"}}>{selected.rule_id}</span>
                {" · "}MITRE <span style={{color:"#00d4ff"}}>{selected.mitre}</span> / <span style={{color:TACTIC_CLR[selected.tactic]||"#4dc9ff"}}>{selected.tactic}</span>
                {" · "}Agent <span style={{color:"#e8ecf4"}}>{selected.agent}</span> ({selected.agentIp})
              </div>
            </div>
            <div style={{textAlign:"center"}}>
              <div style={{fontSize:48,fontWeight:800,fontFamily:"monospace",color:rC(selected.score),lineHeight:1}}>{selected.score}</div>
              <div style={{fontSize:11,color:"#8892a4",marginTop:4}}>Risk Score / 100</div>
              <div style={{marginTop:8}}>
                <Badge color={selected.action==="auto_response"?"#ff2d55":"#ff8c42"}>
                  {selected.action==="auto_response"?"Process Killed":selected.action==="create_case"?"Case Created":"Logged"}
                </Badge>
              </div>
            </div>
          </div>

          <div style={panel}>
            <div style={pt}><Target size={14} color="#00d4ff"/> Component scores</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:20}}>
              <div>
                <ScoreBar label="Wazuh Severity" value={selected.scores?.wazuh||0} weight="40%" color="#00d4ff"/>
                <ScoreBar label="ML Confidence" value={selected.scores?.ml||0} weight="30%" color="#c44dff"/>
              </div>
              <div>
                <ScoreBar label="AbuseIPDB" value={selected.scores?.abuse||0} weight="20%" color="#ff8c42"/>
                <ScoreBar label="VirusTotal" value={selected.scores?.vt||0} weight="10%" color="#ffd84d"/>
              </div>
            </div>
            <div style={{marginTop:12,padding:10,background:"rgba(255,255,255,0.02)",borderRadius:6,fontSize:12,color:"#8892a4",fontFamily:"monospace"}}>
              score = ({selected.scores?.wazuh||0}×0.40) + ({selected.scores?.ml||0}×0.30) + ({selected.scores?.abuse||0}×0.20) + ({selected.scores?.vt||0}×0.10) = <span style={{color:rC(selected.score),fontWeight:700}}>{selected.score}</span>
            </div>
          </div>

          <div style={{display:"flex",gap:4,background:"rgba(255,255,255,0.03)",borderRadius:8,padding:4,width:"fit-content"}}>
            {[{key:"overview",label:"Overview",icon:FileText},{key:"ai",label:"AI Analysis",icon:Bot},{key:"tasks",label:"Response Tasks",icon:ListChecks}].map(t=>(
              <button key={t.key} onClick={()=>{setTab(t.key);if(t.key==="ai"&&!ai.result&&!ai.loading)ai.analyze(selected);}}
                style={{display:"flex",alignItems:"center",gap:6,padding:"8px 16px",borderRadius:6,border:"none",background:tab===t.key?"rgba(0,212,255,0.1)":"transparent",color:tab===t.key?"#00d4ff":"#8892a4",cursor:"pointer",fontSize:12,fontWeight:500}}>
                <t.icon size={13}/> {t.label}
              </button>
            ))}
          </div>

          {tab==="overview"&&(
            <div style={panel}>
              <div style={pt}><Eye size={14} color="#00d4ff"/> Alert metadata</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12}}>
                {[{l:"Rule ID",v:selected.rule_id},{l:"MITRE",v:selected.mitre},{l:"Tactic",v:selected.tactic},
                  {l:"Agent",v:selected.agent},{l:"Agent IP",v:selected.agentIp},{l:"ML Verdict",v:`${selected.mlVerdict||"unknown"} (${((selected.mlConf||0)*100).toFixed(0)}%)`},
                  {l:"Action",v:selected.action},{l:"Severity",v:selected.severity_label||"N/A"},{l:"Time",v:new Date(selected.time).toLocaleString("en-GB")}
                ].map((item,i)=>(
                  <div key={i} style={{padding:12,background:"rgba(255,255,255,0.02)",borderRadius:8}}>
                    <div style={{fontSize:10,color:"#8892a4",textTransform:"uppercase",letterSpacing:0.5,marginBottom:4}}>{item.l}</div>
                    <div style={{fontSize:13,color:"#e8ecf4",fontFamily:"monospace"}}>{item.v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {tab==="ai"&&(
            <div style={panel}>
              <div style={pt}><Bot size={14} color="#c44dff"/> AI Analysis <span style={{fontSize:10,fontWeight:400}}>powered by Claude</span></div>
              {ai.loading&&<div style={{display:"flex",alignItems:"center",gap:10,padding:20,justifyContent:"center",color:"#8892a4"}}><Loader size={18} style={{animation:"spin 1s linear infinite"}}/> Analyzing...<style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style></div>}
              {ai.error&&<div style={{padding:16,background:"rgba(255,45,85,0.05)",border:"1px solid rgba(255,45,85,0.15)",borderRadius:8,color:"#ff4d6a",fontSize:13}}>{ai.error}<button onClick={()=>ai.analyze(selected)} style={{marginLeft:12,padding:"4px 12px",borderRadius:6,border:"1px solid rgba(255,45,85,0.3)",background:"transparent",color:"#ff4d6a",cursor:"pointer",fontSize:12}}>Retry</button></div>}
              {ai.result&&(
                <div style={{display:"flex",flexDirection:"column",gap:14}}>
                  <div style={{padding:16,background:"rgba(196,77,255,0.04)",border:"1px solid rgba(196,77,255,0.1)",borderRadius:8}}>
                    <div style={{fontSize:12,fontWeight:600,color:"#c44dff",marginBottom:8}}>Threat Summary</div>
                    <div style={{fontSize:13,color:"#c0c8d8",lineHeight:1.7}}>{ai.result.threat_summary}</div>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                    <div style={{padding:16,background:"rgba(0,212,255,0.04)",border:"1px solid rgba(0,212,255,0.1)",borderRadius:8}}>
                      <div style={{fontSize:12,fontWeight:600,color:"#00d4ff",marginBottom:8}}>MITRE {selected.mitre}</div>
                      <div style={{fontSize:13,color:"#c0c8d8",lineHeight:1.6}}>{ai.result.mitre_explanation}</div>
                    </div>
                    <div style={{padding:16,background:"rgba(255,141,66,0.04)",border:"1px solid rgba(255,141,66,0.1)",borderRadius:8}}>
                      <div style={{fontSize:12,fontWeight:600,color:"#ff8c42",marginBottom:8}}>Risk Assessment</div>
                      <div style={{fontSize:13,color:"#c0c8d8",lineHeight:1.6}}>{ai.result.risk_assessment}</div>
                      <div style={{marginTop:10,fontSize:11,color:"#8892a4"}}>False Positive: {ai.result.false_positive_likelihood}</div>
                    </div>
                  </div>
                  <div style={{padding:16,background:"rgba(255,45,85,0.04)",border:"1px solid rgba(255,45,85,0.1)",borderRadius:8}}>
                    <div style={{fontSize:12,fontWeight:600,color:"#ff4d6a",marginBottom:10}}>Immediate Actions</div>
                    {ai.result.immediate_actions?.map((a,i)=>(
                      <div key={i} style={{display:"flex",alignItems:"flex-start",gap:8,padding:"5px 0",borderBottom:i<ai.result.immediate_actions.length-1?"1px solid rgba(255,255,255,0.04)":"none"}}>
                        <ChevronRight size={13} color="#ff4d6a" style={{marginTop:2,flexShrink:0}}/>
                        <span style={{fontSize:13,color:"#c0c8d8"}}>{a}</span>
                      </div>
                    ))}
                  </div>
                  {ai.result.ioc_indicators?.length>0&&(
                    <div style={{padding:16,background:"rgba(255,216,77,0.04)",border:"1px solid rgba(255,216,77,0.1)",borderRadius:8}}>
                      <div style={{fontSize:12,fontWeight:600,color:"#ffd84d",marginBottom:8}}>IOC Indicators</div>
                      <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                        {ai.result.ioc_indicators.map((ioc,i)=><span key={i} style={{padding:"4px 10px",background:"rgba(255,216,77,0.08)",borderRadius:4,fontSize:12,color:"#ffd84d",fontFamily:"monospace"}}>{ioc}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              )}
              {!ai.loading&&!ai.result&&!ai.error&&(
                <button onClick={()=>ai.analyze(selected)} style={{padding:"12px 24px",borderRadius:8,border:"1px solid rgba(196,77,255,0.3)",background:"rgba(196,77,255,0.08)",color:"#c44dff",cursor:"pointer",fontSize:13,fontWeight:500,display:"flex",alignItems:"center",gap:8,margin:"0 auto"}}>
                  <Bot size={16}/> Analyze with Claude
                </button>
              )}
            </div>
          )}

          {tab==="tasks"&&(
            <div style={panel}>
              <div style={pt}><ListChecks size={14} color="#4dff88"/> Response Tasks <span style={{fontSize:10,fontWeight:400,color:"#8892a4"}}>from DeepSeek AI</span></div>
              {selected.tasks&&selected.tasks.length>0?selected.tasks.map((task,i)=>(
                <div key={i} style={{padding:16,marginBottom:10,background:"rgba(255,255,255,0.02)",border:"1px solid rgba(255,255,255,0.05)",borderRadius:8,display:"flex",gap:12}}>
                  <div style={{width:28,height:28,borderRadius:6,background:"rgba(77,255,136,0.1)",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                    <span style={{fontSize:13,fontWeight:700,color:"#4dff88"}}>{i+1}</span>
                  </div>
                  <div style={{flex:1}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                      <span style={{fontSize:14,fontWeight:600,color:"#e8ecf4"}}>{task.title}</span>
                      {task.priority&&<Badge color={task.priority==="HIGH"?"#ff4d6a":task.priority==="MEDIUM"?"#ffd84d":"#4dff88"}>{task.priority}</Badge>}
                    </div>
                    <div style={{fontSize:12,color:"#8892a4",lineHeight:1.6}}>{task.description}</div>
                  </div>
                </div>
              )):(
                <div style={{padding:20,textAlign:"center",color:"#8892a4",fontSize:13}}>
                  No AI tasks for this alert yet.<br/>
                  <span style={{fontSize:11}}>Tasks are generated by DeepSeek in the n8n workflow.</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  }

  return(
    <div style={{background:"#0b0f19",color:"#e8ecf4",fontFamily:"Arial,sans-serif",minHeight:"100vh"}}>
      <div style={{padding:"16px 24px",borderBottom:"1px solid rgba(255,255,255,0.06)",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:10}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <Shield size={24} color="#00d4ff"/>
          <div><span style={{fontSize:18,fontWeight:700}}>SentinelAI</span><span style={{fontSize:12,color:"#8892a4",marginLeft:8}}>SOC Dashboard</span></div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:16}}>
          <ConnStatus connected={connected}/>
          {lastFetch&&<span style={{fontSize:11,color:"#8892a4"}}>Last update: {lastFetch}</span>}
        </div>
      </div>

      <div style={{padding:"16px 24px",display:"flex",flexDirection:"column",gap:16}}>
        {total===0&&(
          <div style={{...panel,textAlign:"center",padding:60}}>
            <Shield size={48} color="#8892a4" style={{margin:"0 auto 16px"}}/>
            <div style={{fontSize:18,fontWeight:600,marginBottom:8}}>Waiting for alerts</div>
            <div style={{fontSize:13,color:"#8892a4"}}>
              {connected?"Backend connected. Run an attack on VM3 or use the test script.":"Cannot connect to backend on VM2:4000. Make sure server.js is running."}
            </div>
            <div style={{marginTop:16,padding:"10px 20px",background:"rgba(255,255,255,0.03)",borderRadius:8,display:"inline-block",fontFamily:"monospace",fontSize:12,color:"#00d4ff"}}>
              cd ~/soc/dashboard && node server.js
            </div>
          </div>
        )}

        {total>0&&(
          <>
            <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:12}}>
              {[
                {icon:Activity,l:"Total Alerts",v:total,s:`${cases} cases`,c:"#00d4ff"},
                {icon:AlertTriangle,l:"Critical",v:critical,s:`${autoResp} killed`,c:"#ff2d55"},
                {icon:Cpu,l:"Avg ML",v:avgML,s:"confidence",c:"#c44dff"},
                {icon:Target,l:"Avg Score",v:avgScore,s:"/ 100",c:"#ff8c42"},
                {icon:Bot,l:"AI Tasks",v:"Active",s:"DeepSeek+Claude",c:"#4dff88"},
              ].map((m,i)=>(
                <div key={i} style={{...panel,padding:"14px 16px"}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                    <m.icon size={14} color={m.c}/>
                    <span style={{fontSize:10,color:"#8892a4",textTransform:"uppercase",letterSpacing:0.8}}>{m.l}</span>
                  </div>
                  <div style={{fontSize:26,fontWeight:700,fontFamily:"monospace",color:"#e8ecf4"}}>{m.v}</div>
                  <div style={{fontSize:11,color:m.c,marginTop:2}}>{m.s}</div>
                </div>
              ))}
            </div>

            <div style={{display:"grid",gridTemplateColumns:"1.2fr 1fr",gap:16}}>
              <div style={panel}>
                <div style={pt}><Activity size={13} color="#00d4ff"/> Alert volume by hour</div>
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={timeData}>
                    <defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#00d4ff" stopOpacity={0.25}/><stop offset="100%" stopColor="#00d4ff" stopOpacity={0}/></linearGradient></defs>
                    <XAxis dataKey="hour" tick={{fill:"#8892a4",fontSize:10}} axisLine={false} tickLine={false}/>
                    <YAxis tick={{fill:"#8892a4",fontSize:10}} axisLine={false} tickLine={false} width={25}/>
                    <Tooltip content={<Tt/>}/>
                    <Area type="monotone" dataKey="alerts" stroke="#00d4ff" fill="url(#ag)" strokeWidth={2} name="Alerts"/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div style={panel}>
                <div style={pt}><Target size={13} color="#ff8c42"/> MITRE tactics</div>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={tacData} layout="vertical">
                    <XAxis type="number" tick={{fill:"#8892a4",fontSize:10}} axisLine={false} tickLine={false}/>
                    <YAxis type="category" dataKey="name" tick={{fill:"#8892a4",fontSize:10}} axisLine={false} tickLine={false} width={120}/>
                    <Tooltip content={<Tt/>}/>
                    <Bar dataKey="value" radius={[0,4,4,0]} name="Count">
                      {tacData.map((d,i)=><Cell key={i} fill={TACTIC_CLR[d.full]||"#4dc9ff"} fillOpacity={0.8}/>)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div style={{display:"flex",gap:16,flexWrap:"wrap"}}>
              <div style={{...panel,flex:1,display:"flex",gap:20,alignItems:"center",justifyContent:"center"}}>
                {sevBuckets.map((b,i)=>(
                  <div key={i} style={{textAlign:"center"}}>
                    <div style={{fontSize:28,fontWeight:700,fontFamily:"monospace",color:b.color}}>{b.count}</div>
                    <div style={{fontSize:10,color:"#8892a4"}}>{b.name}</div>
                  </div>
                ))}
              </div>
              <div style={{...panel,flex:2}}>
                <div style={{fontSize:10,color:"#8892a4",textTransform:"uppercase",letterSpacing:0.8,marginBottom:10}}>Pipeline</div>
                <div style={{display:"flex",gap:4,alignItems:"center",flexWrap:"wrap"}}>
                  {["Sysmon","Wazuh","n8n","VT+Abuse","ML","Risk Score","TheHive","DeepSeek Tasks","Dashboard"].map((s,i,arr)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:4}}>
                      <div style={{padding:"4px 8px",borderRadius:5,background:"rgba(0,212,255,0.06)",border:"1px solid rgba(0,212,255,0.15)",fontSize:10,color:"#00d4ff"}}>{s}</div>
                      {i<arr.length-1&&<span style={{color:"rgba(0,212,255,0.3)",fontSize:11}}>→</span>}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div style={panel}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14,flexWrap:"wrap",gap:8}}>
                <div style={pt}><AlertTriangle size={13} color="#ff8c42"/> Live alerts <span style={{fontWeight:400,fontSize:10,color:"#8892a4"}}>click for AI analysis</span></div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  <div style={{position:"relative"}}>
                    <Search size={12} style={{position:"absolute",left:8,top:8,color:"#8892a4"}}/>
                    <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search..." style={{background:"rgba(255,255,255,0.04)",border:"1px solid rgba(255,255,255,0.06)",borderRadius:6,padding:"6px 8px 6px 26px",color:"#e8ecf4",fontSize:11,width:140,outline:"none"}}/>
                  </div>
                  {["all","critical","high","medium","low"].map(f=>(
                    <button key={f} onClick={()=>setFilter(f)} style={{padding:"4px 10px",borderRadius:5,border:`1px solid ${filter===f?"rgba(0,212,255,0.25)":"rgba(255,255,255,0.06)"}`,background:filter===f?"rgba(0,212,255,0.08)":"transparent",color:filter===f?"#00d4ff":"#8892a4",cursor:"pointer",fontSize:10,textTransform:"capitalize"}}>{f}</button>
                  ))}
                </div>
              </div>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
                  <thead>
                    <tr>{["Time","Rule","Description","MITRE","Agent","Score","ML","Action","Tasks"].map(h=>(
                      <th key={h} style={{textAlign:"left",padding:"6px 8px",color:"#8892a4",fontWeight:500,fontSize:10,textTransform:"uppercase",letterSpacing:0.5,borderBottom:"1px solid rgba(255,255,255,0.06)"}}>{h}</th>
                    ))}</tr>
                  </thead>
                  <tbody>
                    {filtered.slice(0,15).map(a=>(
                      <tr key={a.id} onClick={()=>openAlert(a)} style={{borderBottom:"1px solid rgba(255,255,255,0.03)",cursor:"pointer",transition:"background 0.15s"}}
                        onMouseEnter={e=>e.currentTarget.style.background="rgba(0,212,255,0.03)"}
                        onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                        <td style={{padding:"8px",color:"#8892a4",fontFamily:"monospace",fontSize:10}}>{new Date(a.time).toLocaleTimeString("en-GB")}</td>
                        <td style={{padding:"8px",fontFamily:"monospace",color:"#c0c8d8"}}>{a.rule_id}</td>
                        <td style={{padding:"8px",color:"#e8ecf4",maxWidth:200}}>{a.desc}</td>
                        <td style={{padding:"8px"}}><Badge color={TACTIC_CLR[a.tactic]||"#4dc9ff"}>{a.mitre}</Badge></td>
                        <td style={{padding:"8px",color:"#c0c8d8",fontSize:11}}>{a.agent}</td>
                        <td style={{padding:"8px"}}><Badge color={rC(a.score)}>{a.score}</Badge></td>
                        <td style={{padding:"8px",fontFamily:"monospace",fontSize:11,color:a.mlConf>=0.8?"#ff4d6a":a.mlConf>=0.5?"#ffd84d":"#4dff88"}}>{((a.mlConf||0)*100).toFixed(0)}%</td>
                        <td style={{padding:"8px"}}><Badge color={a.action==="auto_response"?"#ff2d55":a.action==="create_case"?"#ff8c42":"#4dff88"}>{a.action==="auto_response"?"killed":a.action==="create_case"?"case":"log"}</Badge></td>
                        <td style={{padding:"8px",color:a.tasks?.length>0?"#4dff88":"#8892a4",fontSize:11}}>{a.tasks?.length>0?`${a.tasks.length} tasks`:"—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

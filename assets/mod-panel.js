"use strict";
(() => {
  const BACKEND="https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend";
  const qs=new URLSearchParams(location.search);
  const hash=new URLSearchParams(location.hash.replace(/^#/,""));
  let session=qs.get("session")||hash.get("session")||sessionStorage.getItem("streamshield_mod_session")||"";
  const compact=qs.get("compact")==="1";
  if(session){sessionStorage.setItem("streamshield_mod_session",session);}
  history.replaceState(null,"",compact?"/mod-panel?compact=1":"/mod-panel");
  if(compact) document.body.classList.add("mod-panel-compact");

  const error=document.getElementById("mod-error");
  const headers=()=>({"x-streamshield-mod-session":session,accept:"application/json"});
  const fail=(m)=>{error.hidden=false;error.textContent=m;};
  const clearError=()=>{error.hidden=true;error.textContent="";};
  const fmt=v=>v?new Date(v).toLocaleString():"—";
  const esc=s=>String(s??"");

  async function get(path){
    const r=await fetch(BACKEND+path,{headers:headers(),cache:"no-store"});
    const data=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(data.error||"Request failed");
    return data;
  }
  async function post(path,body={}){
    const r=await fetch(BACKEND+path,{method:"POST",headers:{...headers(),"content-type":"application/json"},body:JSON.stringify(body)});
    const data=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(data.error||"Request failed");
    return data;
  }
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));

  async function waitCommand(id){
    for(let i=0;i<45;i++){
      const data=await get("/moderator/command/status?id="+encodeURIComponent(id));
      const c=data.command||{};
      if(c.status==="completed") return c;
      if(c.status==="failed") throw new Error(c.outcome||"Moderator action failed");
      await sleep(1000);
    }
    throw new Error("Action is still queued. Keep the streamer’s StreamShield desktop open.");
  }
  async function runAction(action,row){
    clearError();
    const labels={delete_message:"delete this message",verification_request:"require verification",timeout_10:"timeout this user for 10 minutes",permanent_ban:"permanently ban this user",unban:"unban this user",case_file:"open this case file"};
    if(action!=="case_file" && !confirm("StreamShield: "+(labels[action]||"run this action")+" for "+(row.sender_username?"@"+row.sender_username:"this KICK user")+"?")) return;
    try{
      const cmd=await post("/moderator/command",{action,userId:row.sender_id,username:row.sender_username||"",messageId:row.kick_chat_message_id||""});
      const done=await waitCommand(cmd.command.id);
      if(action==="verification_request"){
        const message=done.result?.ready_message||"";
        if(message){
          try{await navigator.clipboard.writeText(message);alert("Verification message copied. Paste it to the selected viewer.");}
          catch{prompt("Copy and send this verification message:",message);}
        }
      } else if(action==="case_file"){
        showCase(done.result?.caseFile||{});
      } else {
        alert("Completed: "+String(done.outcome||action).replaceAll("_"," "));
      }
      await load();
    }catch(e){fail(e.message||"Moderator action failed");}
  }

  function showCase(c){
    const card=document.getElementById("mod-case-card"),out=document.getElementById("mod-case-output"),title=document.getElementById("mod-case-title");
    title.textContent=(c.username?"@"+c.username:"KICK user "+(c.userId||""))+" · Case "+(c.caseId||"");
    const lines=[
      "RISK SIGNALS",
      ...((c.riskSignals||[]).length?c.riskSignals.map(x=>"• "+x):["No high-confidence repeat-offender signal recorded."]),
      "",
      "VERIFICATION / NETWORK",
      "Verification records: "+(c.verificationMatches?.length||0),
      ...((c.networkMatches||[]).map(x=>"• "+(x.networkLabel||"Verified network")+" · "+(x.blocked?"BLOCKED":"verified"))),
      "",
      "RECENT MODERATION",
      ...((c.actions||[]).slice(0,12).map(x=>"• "+fmt(x.at)+" · "+String(x.action||"").replaceAll("_"," ")+" · "+(x.detail||""))),
      "",
      "RECENT CHAT",
      ...((c.messages||[]).slice(0,12).map(x=>"• "+fmt(x.at)+" · "+(x.content||"")))
    ];
    out.textContent=lines.join("\n");
    card.hidden=false;
    card.scrollIntoView({behavior:"smooth",block:"start"});
  }

  function renderChat(rows){
    const root=document.getElementById("mod-chat");root.replaceChildren();
    if(!rows?.length){root.innerHTML='<p class="mini">No recent chat is available yet.</p>';return;}
    for(const row of rows){
      const wrap=document.createElement("div");wrap.className="mod-chat-row";
      const top=document.createElement("div");top.className="mod-chat-top";
      const who=document.createElement("b");who.textContent=row.sender_username?"@"+row.sender_username:"KICK user "+(row.sender_id||"?");
      const time=document.createElement("span");time.className="mini";time.textContent=fmt(row.event_timestamp);
      top.append(who,time);
      const msg=document.createElement("div");msg.className="mod-chat-message";msg.textContent=row.chat_content||"";
      const actions=document.createElement("div");actions.className="mod-chat-actions";
      const defs=[
        ["Delete","delete_message","secondary"],
        ["Verify","verification_request","secondary"],
        ["10m","timeout_10","secondary"],
        ["Ban","permanent_ban","danger"],
        ["Unban","unban","secondary"],
        ["Case","case_file","secondary"]
      ];
      for(const [label,action,cls] of defs){const b=document.createElement("button");b.className="button small "+cls;b.textContent=label;b.onclick=()=>runAction(action,row);actions.append(b);}
      wrap.append(top,msg,actions);root.append(wrap);
    }
  }
  function renderVerification(rows){
    const root=document.getElementById("mod-verification");root.replaceChildren();
    if(!rows?.length){root.innerHTML='<p class="mini">No recent verification requests.</p>';return;}
    for(const row of rows.slice(0,12)){
      const d=document.createElement("div");d.className="mod-mini-row";
      const who=document.createElement("b");who.textContent=row.kick_username?"@"+row.kick_username:"KICK user "+row.kick_user_id;
      const s=document.createElement("span");s.className="status "+((row.status==="blocked"||row.status==="review")?"error":"");s.textContent=String(row.status||"").toUpperCase();
      d.append(who,s);root.append(d);
    }
  }
  function renderNetworks(rows){
    const root=document.getElementById("mod-networks");root.replaceChildren();
    const shown=(rows||[]).filter(x=>x.blocked).slice(0,12);
    if(!shown.length){root.innerHTML='<p class="mini">No blocked verified networks.</p>';return;}
    for(const row of shown){
      const d=document.createElement("div");d.className="mod-mini-row";
      const id=document.createElement("code");id.textContent=row.network_label||"Verified network";
      const s=document.createElement("span");s.className="status error";s.textContent="BLOCKED";
      d.append(id,s);root.append(d);
    }
  }
  function renderCommands(rows){
    const root=document.getElementById("mod-commands");root.replaceChildren();
    if(!rows?.length){root.innerHTML='<p class="mini">No remote actions yet.</p>';return;}
    for(const row of rows.slice(0,12)){
      const d=document.createElement("div");d.className="mod-command-row";
      const name=document.createElement("b");name.textContent=String(row.action||"action").replaceAll("_"," ");
      const state=document.createElement("span");state.className="status "+(row.status==="failed"?"error":row.status==="completed"?"":"warning");state.textContent=String(row.status||"").toUpperCase();
      const meta=document.createElement("small");meta.textContent=(row.outcome?String(row.outcome).replaceAll("_"," ")+" · ":"")+fmt(row.created_at);
      d.append(name,state,meta);root.append(d);
    }
  }
  async function load(){
    if(!session){fail("No moderator session. Open the private invite the streamer sent you.");return;}
    try{
      const data=await get("/moderator/snapshot");clearError();
      const channel=data.channel||{},mod=data.moderator||{};
      document.getElementById("mod-channel").textContent=channel.slug?"@"+channel.slug:"StreamShield Mod Dashboard";
      document.getElementById("mod-identity").textContent=(mod.kick_username?"Signed in as @"+mod.kick_username:"Selected moderator");
      document.getElementById("mod-last-event").textContent=channel.last_webhook_at?fmt(channel.last_webhook_at):"Waiting";
      document.getElementById("mod-desktop-status").textContent=(data.commands||[]).some(x=>x.status==="claimed")?"Working":"Ready";
      document.getElementById("mod-permissions").textContent="Verify · Delete · Timeout · Ban · Unban · Case files";
      renderChat(data.recent_chat||[]);renderVerification(data.verification||[]);renderNetworks(data.networks||[]);renderCommands(data.commands||[]);
    }catch(e){
      fail(e.message==="moderator_session_invalid"?"Your moderator access expired or was revoked. Ask the streamer for a new invite.":e.message);
    }
  }

  document.getElementById("mod-refresh").onclick=load;
  document.getElementById("mod-popout").onclick=()=>window.open("/mod-panel?compact=1#session="+encodeURIComponent(session),"streamshieldModCompact","popup=yes,width=520,height=760,resizable=yes,scrollbars=yes");
  document.getElementById("mod-logout").onclick=async()=>{try{await post("/moderator/logout");}catch{}sessionStorage.removeItem("streamshield_mod_session");session="";location="/mods";};
  document.getElementById("mod-case-close").onclick=()=>document.getElementById("mod-case-card").hidden=true;
  load();setInterval(load,3000);
})();
const events=['chat.message.sent','channel.followed','livestream.status.updated','livestream.metadata.updated','moderation.banned'];
const response=(x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'content-type':'application/json'}});
globalThis.fetch=async (raw,init={})=>{
 const url=new URL(String(raw));const p=url.pathname;const method=init.method||'GET';
 if(url.hostname==='api.kick.com'){
  if(p.endsWith('/events/subscriptions')) return response({data:events.map(event=>({event,version:1,method:'webhook'}))});
  if(p.endsWith('/livestreams')) return response({data:[]});
  if(p.endsWith('/moderation/bans')) {process.stdout.write('MOCK_KICK_'+method+'\n');return response({data:{}});}
 }
 if(url.hostname==='qa.invalid'){
  if(p.endsWith('/release/latest'))return response({ok:true,release:null});
  if(p.endsWith('/events'))return response({ok:true,events:[]});
  if(p.endsWith('/network/status'))return response({ok:true,network:{enabled:false,auto_ban_exact_network_match:false,blocked_networks:1}});
  if(p.endsWith('/network/history'))return response({ok:true,history:[{network_hash:'a'.repeat(64),ip:'192.0.2.20',blocked:true}]});
  if(p.endsWith('/network/queue')||p.endsWith('/verification/queue')||p.endsWith('/verification/recent')||p.endsWith('/moderator/install/commands'))return response({ok:true,items:[]});
  if(p.endsWith('/moderator/install/access'))return response({ok:true,moderators:[],pending_invites:[]});
  if(p.endsWith('/verification/complete'))return response({ok:true,completed:true});
  if(p.endsWith('/status'))return response({ok:true,channel:{broadcaster_id:910000001}});
 }
 throw new Error('QA outbound network blocked: '+url.origin+p);
};

"use strict";
(() => {
  const BACKEND="https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend";
  const invite=new URLSearchParams(location.search).get("invite")||"";
  const status=document.getElementById("mod-invite-status");
  const details=document.getElementById("mod-invite-details");
  const copy=document.getElementById("mod-invite-copy");
  const connect=document.getElementById("mod-connect");
  const fail=(message)=>{status.textContent=message;status.classList.add("error");details.hidden=true;};
  if(!/^[A-Za-z0-9_-]{32,128}$/.test(invite)){fail("This moderator invite is invalid. Ask the streamer for a new invite.");return;}
  fetch(BACKEND+"/moderator/invite-info?invite="+encodeURIComponent(invite),{headers:{accept:"application/json"},cache:"no-store"})
    .then(async r=>({ok:r.ok,data:await r.json().catch(()=>({}))}))
    .then(({ok,data})=>{
      if(!ok) throw new Error("This moderator invite has expired or was revoked.");
      const username=data?.invite?.kick_username?"@"+data.invite.kick_username:"the selected KICK account";
      const channel=data?.channel?.slug?"@"+data.channel.slug:"this KICK channel";
      status.textContent="Invite verified";
      status.classList.remove("error");
      copy.textContent="You were selected to help moderate "+channel+" as "+username+".";
      connect.href=BACKEND+"/moderator/start?invite="+encodeURIComponent(invite);
      details.hidden=false;
    })
    .catch(e=>fail(e.message||"Could not verify this moderator invite."));
})();
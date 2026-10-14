"use strict";
(async()=>{
 const box=document.getElementById("policy-status");
 try {
  const response=await fetch("https://blrdvuhnxtwnsphdxpkg.supabase.co/functions/v1/streamshield-backend/client/policy",{cache:"no-store",signal:AbortSignal.timeout(8000)});
  if(!response.ok) throw new Error("Policy unavailable");
  const data=await response.json();
  box.textContent=data.enforced?"Required version: "+String(data.minimum_version)+" or newer. Install the current build and reconnect StreamShield.":"Available build: 0.6.0-beta.14. Required-update enforcement is not currently active.";
 }catch{box.textContent="Available build: 0.6.0-beta.14. Cloud update policy could not be checked; follow the installation steps below.";}
})();

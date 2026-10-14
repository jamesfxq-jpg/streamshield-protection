// Compatibility and session checks do not attest installed files or retroactively
// cancel already-issued KICK calls. Never carry a lease across reauthorization.
export function createClientSessionGuard({check, expire, now=Date.now, leaseMs=30000}) {
    const leases=new WeakMap(), pending=new WeakMap();
    const identity=s=>String(s.id||"")+"|"+String(s.remoteInstallKey||"");
    return async function requireCurrentSession(session) {
        if(session.reauthRequired)throw Object.assign(new Error(session.clientSessionMessage||"Reconnect StreamShield after updating."),{status:401});
        const generation=identity(session), lease=leases.get(session), flight=pending.get(session);
        if(lease?.generation===generation&&now()<lease.until)return;
        if(flight?.generation===generation)return flight.task;
        const task=Promise.resolve().then(async()=>{
            try {
                const result=await check(session);
                if(identity(session)!==generation)throw new Error("StreamShield sign-in changed during this request. Try the action again.");
                if(result?.ok!==true)throw new Error("StreamShield session check could not be confirmed.");
                if(session.reauthRequired)throw Object.assign(new Error("Your StreamShield session has ended."),{status:401});
                leases.set(session,{generation,until:now()+leaseMs});
            }catch(error){
                if(identity(session)===generation){
                    leases.delete(session);
                    if(error.status===401||error.status===426||error.signOut)await expire(session,error.message);
                }
                throw error;
            }finally{if(pending.get(session)?.task===task)pending.delete(session);}
        });
        pending.set(session,{generation,task});return task;
    };
}
export function expireClientSession(session,message) {
    // Preserve policy choices, verification ownership and permanent-ban holds.
    session.reauthRequired=true;
    session.clientSessionMessage=message||"Install the current StreamShield update and reconnect with KICK.";
    session.token={};session.tokenExpiresAt=0;
    session.remoteBackendRegistered=false;
    session.remoteBackendError=session.clientSessionMessage;
}

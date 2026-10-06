import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const SITE = "https://streamshield-protection-public.vercel.app";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const AREAS = new Set(["install","kick_connect","prestream","compact","chat","verification","network","moderation","recovery","reports","obs","update","other"]);
const OUTCOMES = new Set(["worked","worked_with_issue","failed","suggestion"]);
const SEVERITIES = new Set(["none","low","medium","high","critical"]);

function redirect(path: string, status = 303) {
  return new Response(null,{status,headers:{"location":SITE+path,"cache-control":"no-store, max-age=0","referrer-policy":"no-referrer","x-content-type-options":"nosniff"}});
}
function clean(value: string | null, max: number) { return (value || "").replace(/\r\n/g,"\n").trim().slice(0,max); }
function fail(code: string) { return redirect("/beta?error="+encodeURIComponent(code)+"#feedback"); }

Deno.serve(async (req: Request) => {
  if (req.method === "GET") return redirect("/beta");
  if (req.method !== "POST") return new Response("Method not allowed",{status:405,headers:{"allow":"GET, POST"}});
  const origin=req.headers.get("origin"), referer=req.headers.get("referer")||"";
  if(origin!==SITE && !referer.startsWith(SITE+"/beta")) return fail("origin");
  const contentType=req.headers.get("content-type")||"";
  if(!contentType.toLowerCase().startsWith("application/x-www-form-urlencoded")) return fail("format");
  const contentLength=Number(req.headers.get("content-length")||"0");
  if(contentLength>30000) return fail("too_large");
  const body=await req.text();
  if(body.length>30000) return fail("too_large");
  const form=new URLSearchParams(body);
  if(clean(form.get("company_website"),200)) return redirect("/beta-thanks?ref=RECEIVED");
  if(form.get("beta_acknowledged")!=="on") return fail("acknowledgement");
  const windows_version=clean(form.get("windows_version"),80);
  const streamshield_version=clean(form.get("streamshield_version"),40);
  const test_area=clean(form.get("test_area"),30);
  const outcome=clean(form.get("outcome"),30);
  const severity=clean(form.get("severity"),30);
  const summary=clean(form.get("summary"),600);
  if(!windows_version||!streamshield_version||!AREAS.has(test_area)||!OUTCOMES.has(outcome)||!SEVERITIES.has(severity)||summary.length<8) return fail("required");
  const email=clean(form.get("email"),254);
  if(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("email");
  const public_ref="SSB-"+crypto.randomUUID().split("-")[0].toUpperCase();
  const record={public_ref,tester_name:clean(form.get("tester_name"),100)||null,kick_username:clean(form.get("kick_username"),80)||null,email:email||null,windows_version,streamshield_version,test_area,outcome,severity,summary,reproduction_steps:clean(form.get("reproduction_steps"),2500)||null,expected_result:clean(form.get("expected_result"),1500)||null,actual_result:clean(form.get("actual_result"),1500)||null,notes:clean(form.get("notes"),2000)||null,contact_opt_in:form.get("contact_opt_in")==="on"};
  if(!SUPABASE_URL||!SERVICE_KEY) return fail("service");
  const upstream=await fetch(SUPABASE_URL+"/rest/v1/streamshield_beta_feedback",{method:"POST",headers:{"apikey":SERVICE_KEY,"authorization":"Bearer "+SERVICE_KEY,"content-type":"application/json","prefer":"return=minimal"},body:JSON.stringify(record)});
  if(!upstream.ok){console.error("beta feedback insert failed",upstream.status,await upstream.text());return fail("service");}
  return redirect("/beta-thanks?ref="+encodeURIComponent(public_ref));
});

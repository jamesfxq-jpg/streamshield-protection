// Compatibility metadata is not executable-file attestation. Identity and epoch
// checks below are separate from the client-reported version.
export function compareClientVersions(left: unknown, right: unknown): number | null {
  const parse=(value:unknown)=>{
    if(typeof value!=="string") return null;
    const m=/^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})(?:-beta\.(0|[1-9]\d{0,3}))?$/.exec(value);
    return m?[Number(m[1]),Number(m[2]),Number(m[3]),m[4]===undefined?10000:Number(m[4])]:null;
  };
  const a=parse(left),b=parse(right);if(!a||!b)return null;
  for(let i=0;i<a.length;i++)if(a[i]!==b[i])return a[i]>b[i]?1:-1;
  return 0;
}
export function supportedClientVersion(value:unknown, minimum:unknown):boolean {
  const compared=compareClientVersions(value,minimum);return compared!==null&&compared>=0;
}
export function currentAuthEpoch(value:unknown, epoch:unknown):boolean {
  return Number.isSafeInteger(value)&&Number.isSafeInteger(epoch)&&Number(value)>=0&&value===epoch;
}

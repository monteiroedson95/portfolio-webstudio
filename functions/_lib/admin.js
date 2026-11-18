export const ADMIN_EMAIL='contato.nosdesites@gmail.com';
export const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY'}});
const enc=new TextEncoder();
export const b64=(data)=>btoa(String.fromCharCode(...new Uint8Array(data))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64=(s)=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
export async function mac(secret,msg){const k=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return b64(await crypto.subtle.sign('HMAC',k,enc.encode(msg)));}
export function configured(env){return !!(env.DB&&env.ADMIN_SESSION_SECRET&&env.RESEND_API_KEY);}
export function validOrigin(request){const o=request.headers.get('Origin');return !!o&&o===new URL(request.url).origin&&request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json');}
export async function bodyJson(request){const s=await request.text();if(s.length>3000)throw Error('large');return JSON.parse(s);}
export async function ipHash(request,secret){return mac(secret,'ip:'+ (request.headers.get('CF-Connecting-IP')||'unknown'));}
export async function rateLimit(env,key,max=5){const window=Math.floor(Date.now()/3600000);const row=await env.DB.prepare(`INSERT INTO admin_login_limits (ip_hash, janela, quantidade) VALUES (?, ?, 1) ON CONFLICT(ip_hash, janela) DO UPDATE SET quantidade=quantidade+1 WHERE quantidade < ? RETURNING quantidade`).bind(key,window,max).first();return !!row;}
export async function session(env,request){const cookie=request.headers.get('Cookie')||'';const match=cookie.match(/(?:^|;\s*)nosde_admin=([^;]+)/);if(!match)return false;const parts=match[1].split('.');if(parts.length!==2)return false;try{const [payload,sig]=parts;const expected=await mac(env.ADMIN_SESSION_SECRET,'session:'+payload);if(sig.length!==expected.length)return false;let diff=0;for(let i=0;i<sig.length;i++)diff|=sig.charCodeAt(i)^expected.charCodeAt(i);if(diff)return false;const d=JSON.parse(new TextDecoder().decode(unb64(payload)));return d.email===ADMIN_EMAIL&&Number.isFinite(d.exp)&&d.exp>Date.now()&&d.exp<=Date.now()+8*3600000;}catch{return false;}}
export async function makeCookie(env){const payload=b64(enc.encode(JSON.stringify({email:ADMIN_EMAIL,exp:Date.now()+8*3600000})));const sig=await mac(env.ADMIN_SESSION_SECRET,'session:'+payload);return `nosde_admin=${payload}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;}
export const clearCookie='nosde_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0';

import {ADMIN_EMAIL,json,configured,validOrigin,bodyJson,mac,ipHash,rateLimit,makeCookie} from '../../_lib/admin.js';
export async function onRequestPost({request,env}){
 if(!configured(env))return json({error:'Configuração do painel incompleta.'},503);
 if(!validOrigin(request))return json({error:'Requisição não autorizada.'},403);
 let d;try{d=await bodyJson(request);}catch{return json({error:'Dados inválidos.'},400);}
 if(!d||d.email?.trim()?.toLowerCase()!==ADMIN_EMAIL||typeof d.code!=='string'||!/^[0-9]{6}$/.test(d.code))return json({error:'Código inválido.'},400);
 try{
  const ip=await ipHash(request,env.ADMIN_SESSION_SECRET);
  if(!await rateLimit(env,await mac(env.ADMIN_SESSION_SECRET,'verify:'+ip),15))return json({error:'Muitas tentativas. Tente mais tarde.'},429);
  const now=Math.floor(Date.now()/1000);
  const hash=await mac(env.ADMIN_SESSION_SECRET,'code:'+ADMIN_EMAIL+':'+d.code);
  const result=await env.DB.prepare('UPDATE admin_login_codes SET used_at=? WHERE id=(SELECT id FROM admin_login_codes WHERE email=? AND code_hash=? AND used_at IS NULL AND expires_at>? AND attempts<5 ORDER BY id DESC LIMIT 1) AND used_at IS NULL RETURNING id').bind(now,ADMIN_EMAIL,hash,now).first();
  if(!result){await env.DB.prepare('UPDATE admin_login_codes SET attempts=attempts+1 WHERE email=? AND used_at IS NULL AND expires_at>? AND attempts<5').bind(ADMIN_EMAIL,now).run();return json({error:'Código incorreto, expirado ou já utilizado.'},401);}
  const headers=new Headers({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Set-Cookie':await makeCookie(env),'X-Content-Type-Options':'nosniff'});
  return new Response(JSON.stringify({sucesso:true}),{status:200,headers});
 }catch(e){console.error('Validação do código',e);return json({error:'Não foi possível validar o código.'},500);}
}

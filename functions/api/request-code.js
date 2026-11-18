import {ADMIN_EMAIL,json,configured,validOrigin,bodyJson,mac,ipHash,rateLimit} from '../../_lib/admin.js';
export async function onRequestPost({request,env}){
 if(!configured(env))return json({error:'Configuração do painel incompleta.'},503);
 if(!validOrigin(request))return json({error:'Requisição não autorizada.'},403);
 let d;try{d=await bodyJson(request);}catch{return json({error:'Dados inválidos.'},400);}
 if(!d||typeof d.email!=='string'||d.email.trim().toLowerCase()!==ADMIN_EMAIL)return json({error:'Acesso não autorizado.'},403);
 try{
  const ip=await ipHash(request,env.ADMIN_SESSION_SECRET);
  const emailKey=await mac(env.ADMIN_SESSION_SECRET,'email:'+ADMIN_EMAIL);
  if(!await rateLimit(env,ip,5)||!await rateLimit(env,emailKey,8))return json({error:'Muitas solicitações. Tente novamente mais tarde.'},429);
  const num=crypto.getRandomValues(new Uint32Array(1))[0]%1000000;
  const code=String(num).padStart(6,'0');
  const hash=await mac(env.ADMIN_SESSION_SECRET,'code:'+ADMIN_EMAIL+':'+code);
  const now=Math.floor(Date.now()/1000);
  await env.DB.prepare('DELETE FROM admin_login_codes WHERE email=?').bind(ADMIN_EMAIL).run();
  await env.DB.prepare('INSERT INTO admin_login_codes (email,code_hash,expires_at,attempts,used_at,created_at) VALUES (?,?,?,?,NULL,?)').bind(ADMIN_EMAIL,hash,now+600,0,now).run();
  const response=await fetch('https://api.resend.com/emails',{method:'POST',headers:{Authorization:'Bearer '+env.RESEND_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:'NOSDE SITES <onboarding@resend.dev>',to:[ADMIN_EMAIL],subject:'Seu código de acesso — NOSDE SITES',text:`Seu código de acesso é: ${code}\n\nVálido por 10 minutos. Se você não solicitou, ignore esta mensagem.`})});
  if(!response.ok){console.error('Resend erro',response.status,await response.text());return json({error:'Não foi possível enviar o código. Confira a configuração do Resend.'},502);}
  return json({sucesso:true,mensagem:'Código enviado ao e-mail da NOSDE.'});
 }catch(e){console.error('Solicitação de código',e);return json({error:'Não foi possível solicitar o código.'},500);}
}

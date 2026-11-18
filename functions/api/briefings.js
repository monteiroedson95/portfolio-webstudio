import {json,session} from '../../_lib/admin.js';
export async function onRequestGet({request,env}){
 if(!env.DB||!env.ADMIN_SESSION_SECRET)return json({error:'Serviço indisponível.'},503);
 if(!await session(env,request))return json({error:'Acesso não autorizado.'},401);
 try{const {results=[]}=await env.DB.prepare('SELECT id,empresa,responsavel,whatsapp,email,respostas,status,criado_em FROM briefings ORDER BY id DESC LIMIT 100').all();return json({briefings:results.map(({respostas,...rest})=>({...rest,respostas:parse(respostas)}))});}
 catch(e){console.error('Consulta admin',e);return json({error:'Erro ao consultar briefings.'},500);}
}
function parse(v){try{const r=JSON.parse(v);return r&&typeof r==='object'&&!Array.isArray(r)?r:{};}catch{return {};}}

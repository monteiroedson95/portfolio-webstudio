import {json,session} from '../../_lib/admin.js';
export async function onRequestGet({request,env}){if(!env.ADMIN_SESSION_SECRET)return json({autenticado:false},503);return json({autenticado:await session(env,request)});}

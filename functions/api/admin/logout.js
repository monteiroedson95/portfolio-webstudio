import {json,clearCookie,validOrigin} from '../../_lib/admin.js';
export async function onRequestPost({request}){if(!validOrigin(request))return json({error:'Origem inválida.'},403);const r=json({sucesso:true});r.headers.set('Set-Cookie',clearCookie);return r;}

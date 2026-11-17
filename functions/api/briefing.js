const reply = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }
});

export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.TURNSTILE_SECRET) return reply({ error: 'Serviço em configuração.' }, 503);
  const origin = request.headers.get('Origin');
  if (!origin || origin !== new URL(request.url).origin) return reply({ error: 'Origem não autorizada.' }, 403);
  if (!request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) return reply({ error: 'Formato inválido.' }, 415);
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > 20000) return reply({ error: 'Dados muito extensos.' }, 413);
  let dados;
  try {
    const body = await request.text();
    if (body.length > 20000) return reply({ error: 'Dados muito extensos.' }, 413);
    dados = JSON.parse(body);
  } catch { return reply({ error: 'Dados inválidos.' }, 400); }
  if (!dados || typeof dados !== 'object' || Array.isArray(dados)) return reply({ error: 'Dados inválidos.' }, 400);
  if (dados.website) return reply({ sucesso: true }, 201); // honeypot
  const empresa = typeof dados.empresa === 'string' ? dados.empresa.trim() : '';
  const responsavel = typeof dados.responsavel === 'string' ? dados.responsavel.trim() : '';
  const whatsapp = typeof dados.whatsapp === 'string' ? dados.whatsapp.trim() : '';
  const email = typeof dados.email === 'string' ? dados.email.trim() : '';
  if (!empresa || !responsavel || !whatsapp || empresa.length > 150 || responsavel.length > 150 ||
      whatsapp.length > 30 || !/^[+()\d\s-]{8,30}$/.test(whatsapp) || email.length > 254 ||
      (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) return reply({ error: 'Confira os campos obrigatórios.' }, 400);
  const respostas = dados.respostas;
  if (!respostas || typeof respostas !== 'object' || Array.isArray(respostas)) return reply({ error: 'Respostas inválidas.' }, 400);
  const camposPermitidos = new Set(['Empresa','Responsável','WhatsApp','E-mail','Ramo de atuação','Descrição do negócio','Tipo de site','Objetivo','Páginas e seções','Funcionalidades','Cores','Possui logotipo','Referências','Materiais disponíveis','Domínio','Prazo desejado','Observações']);
  const filtradas = {};
  for (const [key, value] of Object.entries(respostas)) {
    if (!camposPermitidos.has(key) || typeof value !== 'string' || value.length > 2500) return reply({ error: 'Conteúdo inválido.' }, 400);
    filtradas[key] = value;
  }
  const json = JSON.stringify(filtradas);
  if (json.length > 15000) return reply({ error: 'Respostas muito extensas.' }, 400);
  const token = typeof dados.turnstileToken === 'string' ? dados.turnstileToken : '';
  if (!token || token.length > 2048) return reply({ error: 'Confirme a verificação de segurança.' }, 400);
  try {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const ipHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(env.TURNSTILE_SECRET + ':' + ip));
    const ipHash = Array.from(new Uint8Array(ipHashBuffer), b => b.toString(16).padStart(2,'0')).join('');
    const now = Math.floor(Date.now()/1000);
    // 3 submissões por hora por IP; gravação atômica da contagem
    const limit = await env.DB.prepare(`INSERT INTO briefing_rate_limit (ip_hash, janela, quantidade)
      VALUES (?, ?, 1) ON CONFLICT(ip_hash, janela) DO UPDATE SET quantidade = quantidade + 1
      WHERE quantidade < 3 RETURNING quantidade`).bind(ipHash, Math.floor(now / 3600)).first();
    if (!limit) return reply({ error: 'Limite de envios atingido. Tente novamente mais tarde.' }, 429);
    const verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip })
    });
    if (!verify.ok) return reply({ error: 'Verificação indisponível. Tente novamente.' }, 503);
    const result = await verify.json();
    if (!result.success || result.hostname !== new URL(request.url).hostname) return reply({ error: 'Verificação de segurança inválida. Atualize a página.' }, 403);
    await env.DB.prepare(`INSERT INTO briefings (empresa, responsavel, whatsapp, email, respostas)
      VALUES (?, ?, ?, ?, ?)`).bind(empresa, responsavel, whatsapp, email, json).run();
    return reply({ sucesso: true, mensagem: 'Briefing recebido!' }, 201);
  } catch (error) {
    console.error('Erro ao registrar briefing', error);
    return reply({ error: 'Não foi possível registrar o briefing.' }, 500);
  }
}

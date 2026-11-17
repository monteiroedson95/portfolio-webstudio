
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });

export async function onRequestPost({ request, env }) {
  try {
    if (!env.DB) {
      return json({ error: "Banco não configurado." }, 503);
    }

    // Aceita apenas requisições da origem do próprio site.
    const origin = request.headers.get("Origin");
    if (!origin || new URL(origin).origin !== new URL(request.url).origin) {
      return json({ error: "Origem não autorizada." }, 403);
    }

    if (!request.headers.get("Content-Type")?.toLowerCase()
      .startsWith("application/json")) {
      return json({ error: "Formato inválido." }, 415);
    }

    const tamanho = Number(request.headers.get("Content-Length"));
    if (tamanho > 20000) {
      return json({ error: "Formulário muito grande." }, 413);
    }

    const texto = await request.text();
    if (texto.length > 20000) {
      return json({ error: "Formulário muito grande." }, 413);
    }

    const dados = JSON.parse(texto);

    if (!dados || typeof dados !== "object" || Array.isArray(dados)) {
      return json({ error: "Dados inválidos." }, 400);
    }

    const empresa = String(dados.empresa ?? "").trim();
    const responsavel = String(dados.responsavel ?? "").trim();
    const whatsapp = String(dados.whatsapp ?? "").trim();
    const email = String(dados.email ?? "").trim();

    if (!empresa || !responsavel || !whatsapp) {
      return json({ error: "Preencha os campos obrigatórios." }, 400);
    }

    if (
      empresa.length > 150 ||
      responsavel.length > 150 ||
      whatsapp.length > 30 ||
      email.length > 254 ||
      (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    ) {
      return json({ error: "Verifique os dados informados." }, 400);
    }

    const respostas = JSON.stringify(dados.respostas ?? {});

    if (respostas.length > 15000) {
      return json({ error: "Respostas muito extensas." }, 400);
    }

    await env.DB.prepare(`
      INSERT INTO briefings
      (empresa, responsavel, whatsapp, email, respostas)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      empresa,
      responsavel,
      whatsapp,
      email,
      respostas
    ).run();

    return json({ sucesso: true, mensagem: "Briefing recebido!" }, 201);

  } catch (erro) {
    if (erro instanceof SyntaxError) {
      return json({ error: "JSON inválido." }, 400);
    }

    console.error("Erro ao salvar briefing:", erro);
    return json({ error: "Não foi possível salvar o briefing." }, 500);
  }
}

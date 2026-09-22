# VibeGuard

*[English](README.md) · [Português](README.pt-BR.md)*

**Guardrails de segurança para quem entrega rápido com IA.**

Você construiu a coisa em um fim de semana. Funciona. Pessoas reais estão a ponto de
colocar ali o e-mail, os dados e talvez o cartão de crédito delas. O VibeGuard é a
parte que ninguém te ensinou: as verificações que acontecem antes de isso dar errado.

É um plugin do [Claude Code](https://claude.com/claude-code) — quatro skills, um agente
revisor e um hook que nunca dorme.

```shell
/plugin marketplace add carvalhxlucas/vibe-guard
/plugin install vibe-guard@vibe-guard
```

---

## Por que isso existe

Ferramentas de código com IA são muito boas em fazer as coisas funcionarem e
completamente indiferentes a se elas são seguras. Os mesmos sete problemas aparecem em
quase todo app construído desse jeito:

| O problema | O que acontece na prática |
|---|---|
| Chaves de API hardcoded, ou atrás de `NEXT_PUBLIC_` | Qualquer pessoa que abrir o JavaScript do seu site lê suas chaves. Bots varrem repositórios públicos em busca delas poucos minutos depois de um push. |
| Row Level Security desligado no Supabase | A chave anon é pública por design. Com RLS desligado, "público" significa que toda linha de toda tabela pode ser lida por qualquer um. |
| Rotas de API sem checagem de autenticação | Server actions e route handlers são endpoints HTTP públicos. Sem checagem, `POST /api/delete-account` funciona para qualquer pessoa. |
| Sem validação de entrada, sem rate limit | Um tipo do TypeScript não é validação — tipos desaparecem em runtime. Um endpoint sem autenticação que chama uma API de IA é uma fatura esperando para acontecer. |
| CORS liberado | `Access-Control-Allow-Origin: *` junto com credenciais permite que qualquer site faça requisições como seus usuários logados. |
| Nenhuma higiene de deploy | Stack traces exibidos para usuários, segredos em logs, headers de HTTPS faltando, `.env` commitado meses atrás e ainda válido. |
| Uma requisição derruba o app | Uma query sem `limit` numa tabela que cresceu, uma conexão de banco aberta por requisição, um body de 50MB parseado antes de qualquer validação. Não precisa de volume — o app simplesmente fica indisponível, para todos, quando alguém quiser. |

Nenhum desses casos exige um atacante habilidoso. Exige alguém curioso com o dev tools
do navegador aberto.

**Para quem é:** desenvolvedores indie e fundadores solo entregando com Cursor,
Lovable, bolt.new, v0 ou Claude Code — tipicamente Next.js/React + Supabase ou Postgres
+ Vercel. As verificações são escritas pelo que procuram, não pelo framework, então a
maior parte funciona em qualquer lugar. Nenhum conhecimento prévio de segurança é
assumido.

---

## O que vem na caixa

### 🔍 `/vibe-guard:security-audit` — descubra o que está errado

Varre o projeto em nove áreas e escreve `SECURITY-AUDIT.md`: segredos expostos, RLS,
autorização em rotas de API, validação de entrada, rate limiting, CORS, headers de
segurança, dependências e higiene de erros, e esgotamento de recursos — queries sem
limite, uma conexão por requisição, bodies e uploads sem teto, chamadas externas sem
timeout, uma regex que trava com uma entrada curta.

Cada achado recebe uma severidade e quatro campos — **o que é** em linguagem simples,
**por que importa** nos termos do seu app, **onde** (`arquivo:linha`, com segredos
redigidos) e **como corrigir** neste código. O relatório informa o que foi verificado e
lista o que não deu para checar, para você conhecer os limites.

Ele nunca edita seu código. Depois de ler e decidir, peça as correções.

### 🔒 `/vibe-guard:rls-check` — tranque o banco de dados

Lê o schema **ao vivo** do Supabase, não seus arquivos de migration — tabelas e
toggles de RLS criados pelo dashboard nunca aparecem no repositório. Reporta quais
tabelas a chave anon pública alcança, classifica cada tabela por padrão de propriedade
e então gera a migration de RLS.

Ele escreve a migration; você aplica. Vem com `verify-rls.sql`, que assume o papel
`anon` para provar que a tranca realmente segura, porque "o app continua funcionando"
não é prova.

### 🔑 `/vibe-guard:secure-auth-setup` — login que se sustenta

Faz o scaffolding do Supabase Auth no Next.js do jeito certo — o contrato de cookies do
`@supabase/ssr`, o formato de middleware que não desloga as pessoas aleatoriamente,
layouts protegidos, server actions — ou endurece a autenticação que você já tem.

Cobre as partes que os tutoriais pulam: verificar o usuário no servidor em vez de
confiar na sessão, roles que ficam em um lugar que o usuário não pode editar, reset de
senha que não revela quais e-mails estão cadastrados, e redirects de OAuth que não são
open redirects.

### 🚀 `/vibe-guard:deploy-checklist` — a passada de pré-lançamento

A maior parte do risco de lançamento não está no seu código — está no dashboard da
Vercel, nas configurações do Supabase e na sua conta da Stripe. Isso percorre sete
seções (segredos, banco de dados, erros e monitoramento, transporte, custo e
disponibilidade, pagamentos, privacidade), separando com clareza **o que foi
verificado no código** do **que só você pode confirmar em um dashboard** — incluindo
os controles de custo e de disponibilidade: teto de gasto, rate limits, conexão de
banco com pooler, timeout de função.

Termina com o plano de rollback, porque saber como desfazer o deploy importa mais às
2h da manhã do que qualquer item de checklist.

### 🤖 Agente `security-reviewer` — revise um diff

Um revisor somente leitura para uma branch ou PR. Disponibilidade conta como segurança
aqui: uma query nova sem limite de linhas, ou um `fetch` sem timeout, é apontada quando
um desconhecido alcança a rota. Só segurança, só o que mudou, sem
notas de estilo e sem enchimento. Um diff sem nada relevante para segurança recebe
"No security findings" e uma linha declarando o escopo.

```shell
> use the security-reviewer agent on my current branch
```

### 🛡️ O hook que bloqueia segredos — sempre ligado

Nada para rodar. Todo `Write` e `Edit` que o Claude faz é checado antes. Se contiver
algo que pareça uma credencial real, a escrita é bloqueada:

```
VibeGuard blocked this write: it contains what looks like a real credential.

• Line 12 — Stripe secret key: sk_live_…xYzB
  A Stripe secret key can create charges, issue refunds, and read every
  customer record on your account.

Do this instead:
  1. Move the value into an environment variable…
```

17 padrões de credencial: AWS, Stripe, OpenAI, Anthropic, Supabase, GitHub, Google,
Slack, SendGrid, Twilio, chaves privadas, URLs de banco com senha e JWTs.

Ele sabe a diferença entre um segredo e uma chave pública — publishable keys da Stripe,
a chave anon do Supabase e `NEXT_PUBLIC_SUPABASE_URL` passam intactas, assim como
escritas em arquivos `.env*`, que é onde segredos devem ficar. Ele também pega o erro
inverso: um segredo real colocado atrás de um prefixo `NEXT_PUBLIC_`.

Matches de alta confiança são bloqueados direto. Os de confiança menor perguntam antes.

**Escapes:** adicione `vibeguard-ignore` em um comentário na mesma linha, ou defina
`VIBEGUARD_DISABLE=1` para a sessão.

---

## Requisitos

- **Claude Code** — qualquer versão recente.
- **Node.js** — o hook que bloqueia segredos é um script Node sem dependências. Se
  `node` não estiver no seu `PATH`, o hook não roda e o resto do plugin continua
  funcionando.
- **Opcional, para rodar `rls-check` contra um banco ao vivo**: `psql` ou o Supabase
  CLI. Sem nenhum dos dois, a skill recai em imprimir o SQL para você colar no SQL
  editor do Supabase, o que não exige nada instalado.

Desenvolvido e testado no macOS. Deve funcionar em qualquer lugar onde Claude Code e
Node funcionem, mas o Windows não foi testado — se o hook se comportar mal lá, uma
issue com a saída de `claude --debug` ajudaria.

## Instalação

```shell
/plugin marketplace add carvalhxlucas/vibe-guard
/plugin install vibe-guard@vibe-guard
```

Depois reinicie o Claude Code, ou rode `/reload-plugins`.

Para experimentar sem instalar:

```bash
git clone https://github.com/carvalhxlucas/vibe-guard
claude --plugin-dir ./vibe-guard/plugins/vibe-guard
```

## Como usar

Rode uma skill pelo nome, ou simplesmente descreva a situação — as skills disparam pelo
que você diz:

| Você diz | O que roda |
|---|---|
| "isso é seguro para lançar?" · "vazei alguma chave?" · "alguém consegue derrubar meu app?" | `security-audit` |
| "outros usuários conseguem ver meus dados?" · "meu Supabase está trancado?" | `rls-check` |
| "adiciona login no meu app" · "como eu protejo essa rota?" | `secure-auth-setup` |
| "vou fazer deploy hoje à noite, tem algo para eu checar?" | `deploy-checklist` |

Uma primeira passada razoável em um app que já existe:

```shell
/vibe-guard:security-audit      # o que está errado
/vibe-guard:rls-check           # fechar o banco de dados
/vibe-guard:deploy-checklist    # tudo que está fora do repositório
```

---

## O que ele não é

O VibeGuard é uma passada rápida e opinativa nos erros que afundam apps pequenos. Não é
um teste de invasão, não é uma auditoria de compliance e não é uma garantia. As skills
leem seu código e, no caso do `rls-check`, seu banco de dados — elas não veem a
configuração da sua hospedagem, seu DNS ou seu tráfego. Falhas de lógica de negócio,
condições de corrida e qualquer coisa específica do seu domínio precisam de uma pessoa.
Todo relatório diz o que não conseguiu checar.

## Desenvolvimento

```bash
git clone https://github.com/carvalhxlucas/vibe-guard
cd vibe-guard

# Carregar em uma sessão sem instalar
claude --plugin-dir ./plugins/vibe-guard

# Validar os manifestos e componentes
claude plugin validate .
claude plugin validate ./plugins/vibe-guard --strict
```

### Testes

```bash
cd tests
npm install
npm test
```

37 verificações, sem rede e sem Postgres para instalar — o PGlite roda Postgres 18 em
wasm:

- **O hook**, acionado exatamente como o Claude Code o aciona: 16 payloads cobrindo
  cada família de credencial, o caminho de pergunta, e os casos que devem passar
  intactos (publishable keys, escritas em `.env`, placeholders, `vibeguard-ignore`).
- **O SQL do `rls-check`**, contra um banco real populado com um schema em formato
  Supabase que tem erros deliberados: toda instrução de `introspect.sql` roda, tabelas
  que vazam ficam acima das trancadas, uma policy `using (true)` é contada como aberta,
  e o padrão de `verify-rls.sql` reporta um vazamento como vazamento enquanto o dono
  continua vendo a própria linha.
- **Todo bloco SQL de `policy-patterns.md`**, compilado contra um schema vazio, porque
  eles são documentados como prontos para copiar.

O comportamento das skills — se cada uma dispara com o texto que um usuário real digita
— é medido por seis casos em `plugins/vibe-guard/evals/`. A ferramenta para rodá-los é
o [`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals), que precisa de
acesso antecipado na sua conta:

```bash
cd plugins/vibe-guard
claude plugin eval . --scaffold --allow-tools Bash Write Edit
```

Sem isso, `tests/run-cases.mjs` roda os mesmos arquivos de caso através de `claude -p` e
aplica os graders cujo cálculo não custa nada — `tool_used`, `regex`, `file_exists`. Os
graders `llm` são reportados como pulados em vez de chutados. Ele chama o CLI do Claude,
então custa cerca de \$2,50 para uma passada completa:

```bash
cd tests
node run-cases.mjs                # todos os casos, com o plugin carregado
node run-cases.mjs --case rls     # um caso
node run-cases.mjs --baseline     # roda também sem o plugin, para comparação
```

Resultado atual: as quatro skills disparam com frases coloquiais como sua primeira
chamada de ferramenta, e a requisição sem relação nenhuma não invoca nenhuma delas.

## Roadmap

- [x] `security-audit` — o relatório
- [x] `rls-check` — estado de RLS ao vivo e policies geradas
- [x] `secure-auth-setup` — scaffolding e hardening de autenticação
- [x] `deploy-checklist` — a passada de pré-lançamento
- [x] `security-reviewer` — agente de revisão de diff
- [ ] Cobertura de frameworks além do Next.js: Remix, SvelteKit, Expo
- [ ] Checagens de dependências e cadeia de suprimentos com dados reais de advisories
- [ ] Uma GitHub Action envolvendo o agente revisor

## Contribuindo

Issues e pull requests são bem-vindos — especialmente novos padrões de segredo e falsos
positivos. Se o hook bloqueou algo que não deveria, isso é um bug que vale reportar:
cole a linha redigida e o nome da regra que aparece na mensagem. Novas verificações são
mais úteis com um caso de eval anexado.

## Licença

MIT — veja [LICENSE](LICENSE).

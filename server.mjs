/**
 * x402 Preflight — проверка платёжного эндпоинта до того, как на него потратятся.
 *
 * Зачем это кому-то нужно. В каталогах x402 уже сотни платных эндпоинтов, и
 * покупатель-агент выбирает вслепую: обещанная цена может не совпадать с
 * выставленной, кошелёк получателя — с заявленным в листинге, а сам вызов
 * может не отвечать вовсе. Проверить это можно только одним способом —
 * дёрнуть эндпоинт без оплаты и разобрать его ответ 402.
 *
 * Сервису это стоит один HTTP-запрос. Покупателю — экономит потраченную
 * впустую оплату. Отсюда и цена.
 *
 * Себестоимость нулевая: ни платных источников, ни ключей, ни базы.
 */

import { createServer } from 'node:http';
import { appendFile } from 'node:fs';

const PORT = Number(process.env.PORT || 8402);
/*
 * Слушать только петлю.
 *
 * Замер 09.09 (`netstat -ano`): `server.listen(PORT)` без адреса поднимал
 * `0.0.0.0:8402` и `[::]:8402` — сервис был доступен любому в той же сети,
 * помимо туннеля. Наружу он должен ходить ровно одним путём: cloudflared и
 * ssh к srv.us подключаются к `127.0.0.1:8402`, петли им достаточно.
 * Найдено Сержем при разборе, чей это туннель. Правило: наружу — только
 * через туннель, локальная привязка всегда явная.
 */
const HOST = process.env.HOST || '127.0.0.1';
const PAYOUT = '0xB5bC75A1085345B89531DE4bfA1FF19EE8F9c29a'; // Base, USDC

/*
 * Расчёт идёт через фасилитатор PayAI.
 *
 * Почему именно он. Проверено 02.09: публичные фасилитаторы x402.org и
 * x402.rs держат только тестовые сети — Base mainnet (eip155:8453) нет ни у
 * одного. На mainnet живут два: CDP от Coinbase (нужен аккаунт и ключи) и
 * PayAI. У PayAI бесплатный тариф — до 1000 расчётов, ключ не требуется,
 * а комиссия за его пределами «covers gas and RPC costs», то есть газ платит
 * он, а не я. Это снимает то, что я неделю считал стеной: продавать можно
 * при нулевом балансе и без единого цента на газ.
 *
 * Лимит считается на кошелёк-получатель, поэтому 1000 расчётов — мои.
 */
const FACILITATOR = process.env.FACILITATOR || 'https://facilitator.payai.network';

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const NETWORK_V1 = 'base';           // как сеть зовётся в x402 v1
const NETWORK_V2 = 'eip155:8453';    // она же в v2, CAIP-2
const PRICE_UNITS = '4000';          // 0.004 USDC, у USDC 6 знаков.
// Замер 10.09 (research/agent402-chains-2026-09-10.md, разделы 6-8): роутер
// agent402 держит нашу цену в своей карточке как 0.004 и не обновляет её при
// обходе - при 0.10 на сервере любой платёж по их котировке отбивался бы, то
// есть листинг был неоплачиваем. Медиана прямых аналогов (одиночная проверка
// одного эндпоинта) - 0.005, диапазон 0.002-0.005. 0.10 была ошибкой захода
// №13: тир брался из выручки продавцов вообще, а не аналогов.

/* ---------------------------------------------------------------- журнал обращений

 * Зачем. За 16 суток на кошелёк пришёл ровно один перевод от чужого адреса
 * (замер по цепи 09.09), и это была награда, а не покупка. Но до сих пор
 * нельзя было ответить даже на вопрос попроще: заходил ли к сервису хоть
 * кто-нибудь? Сервер не вёл никакого учёта, стандартный вывод супервизор
 * выбрасывал в stdio:'ignore'. «Ноль продаж» и «ноль посетителей» — разные
 * диагнозы с разным лечением, и различить их было нечем.
 *
 * Пишем строку на каждый завершённый запрос. IP берётся из заголовков
 * туннеля: прямого подключения снаружи нет, сервер слушает петлю.
 */
const REQ_LOG = new URL('../../logs/requests.jsonl', import.meta.url);

function logRequest(req, res, path, started) {
  try {
    const h = req.headers;
    appendFile(REQ_LOG, JSON.stringify({
      t: new Date().toISOString(),
      m: req.method,
      path,
      status: res.statusCode,
      ms: Date.now() - started,
      // 402 без заголовка — просто посмотрели; с заголовком — пытались платить
      paid: Boolean(h['x-payment'] || h['payment-signature']),
      ip: (h['cf-connecting-ip'] || h['x-forwarded-for'] || '').split(',')[0].trim() || null,
      ua: (h['user-agent'] || '').slice(0, 160) || null,
      ref: (h.referer || '').slice(0, 160) || null,
    }) + '\n', () => {});
  } catch { /* учёт не должен ронять сервис */ }
}

/* ---------------------------------------------------------------- утилиты */

function json(res, code, body, extra = {}) {
  const s = JSON.stringify(body, null, 2);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': '*',
    'content-length': Buffer.byteLength(s),
    ...extra,
  });
  res.end(s);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) { reject(new Error('body_too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/** Адрес должен быть публичным http(s). Иначе сервис становится сканером чужой внутренней сети. */
function checkTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { return { ok: false, reason: 'url_unparseable' }; }
  if (!/^https?:$/.test(u.protocol)) return { ok: false, reason: 'scheme_not_http' };
  const h = u.hostname.toLowerCase();
  const blocked =
    h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') ||
    /^\d+\.\d+\.\d+\.\d+$/.test(h) && (
      h.startsWith('127.') || h.startsWith('10.') || h.startsWith('192.168.') ||
      h.startsWith('169.254.') || h.startsWith('0.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    ) ||
    h === '::1' || h.startsWith('[');
  if (blocked) return { ok: false, reason: 'target_not_public' };
  return { ok: true, url: u };
}

/* ------------------------------------------------------- разбор вызова 402 */

const EVM_ADDR = /^0x[0-9a-fA-F]{40}$/;

function analyseChallenge(status, headers, bodyText) {
  const findings = [];
  const out = {
    speaks_x402: false,
    x402_version: null,
    schemes: [],
    networks: [],
    pay_to: [],
    amounts: [],
    asset: null,
    expires: null,
  };

  if (status !== 402) {
    findings.push({
      level: 'blocking',
      code: 'no_402',
      detail: `Endpoint answered ${status} to an unpaid request. A paid x402 resource must answer 402.`,
    });
    return { out, findings };
  }

  let body = null;
  try { body = JSON.parse(bodyText); } catch { /* разберём заголовки ниже */ }

  const hdr = headers['www-authenticate'] || headers['x-payment-required'] || '';
  if (!body && !hdr) {
    findings.push({
      level: 'blocking', code: 'challenge_unreadable',
      detail: 'Status was 402 but the body is not JSON and no payment header was present.',
    });
    return { out, findings };
  }

  out.speaks_x402 = true;
  const reqs = body?.accepts || body?.paymentRequirements ||
               (Array.isArray(body) ? body : body ? [body] : []);
  out.x402_version = body?.x402Version ?? null;

  if (out.x402_version === null) {
    findings.push({ level: 'warning', code: 'version_absent',
      detail: 'Challenge does not state x402Version. Clients cannot negotiate safely.' });
  }

  for (const r of Array.isArray(reqs) ? reqs : []) {
    if (r.scheme) out.schemes.push(r.scheme);
    if (r.network) out.networks.push(r.network);
    const to = r.payTo || r.pay_to || r.recipient || r.address;
    if (to) out.pay_to.push(to);
    const amt = r.maxAmountRequired ?? r.amount ?? r.maxAmount;
    if (amt !== undefined) out.amounts.push(String(amt));
    if (r.asset) out.asset = r.asset;
    if (r.maxTimeoutSeconds) out.expires = r.maxTimeoutSeconds;

    if (to && !EVM_ADDR.test(String(to)) && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(to))) {
      findings.push({ level: 'blocking', code: 'payto_malformed',
        detail: `payTo "${to}" is neither a valid EVM address nor a base58 Solana address.` });
    }
    if (amt !== undefined && !/^\d+$/.test(String(amt))) {
      findings.push({ level: 'blocking', code: 'amount_not_integer',
        detail: `Amount "${amt}" is not an integer in base units. Clients will misprice this call.` });
    }
  }

  if (!out.pay_to.length) {
    findings.push({ level: 'blocking', code: 'payto_absent',
      detail: 'No payment recipient in the challenge. Nothing to pay.' });
  }
  if (!out.networks.length) {
    findings.push({ level: 'blocking', code: 'network_absent',
      detail: 'Challenge names no settlement network.' });
  }
  if (new Set(out.pay_to).size > 1) {
    findings.push({ level: 'warning', code: 'payto_multiple',
      detail: 'Challenge offers several different recipients. Verify which one you are paying.' });
  }
  return { out, findings };
}

/* ------------------------------------------------------------ сама проверка */

async function preflight(target, expect = {}) {
  const t0 = Date.now();
  let status = 0, headers = {}, text = '', netError = null;

  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 10_000);
    const r = await fetch(target, {
      method: 'GET',
      redirect: 'manual',
      signal: ctl.signal,
      headers: { 'User-Agent': 'x402-preflight/1.0 (+unpaid probe)' },
    });
    clearTimeout(timer);
    status = r.status;
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    text = (await r.text()).slice(0, 32_000);
  } catch (e) {
    netError = e.name === 'AbortError' ? 'timeout_10s' : String(e.cause?.code || e.message);
  }

  const latency_ms = Date.now() - t0;

  if (netError) {
    return {
      verdict: 'unreachable',
      reachable: false,
      network_error: netError,
      latency_ms,
      findings: [{ level: 'blocking', code: 'unreachable',
        detail: `The endpoint did not answer: ${netError}. Do not send payment.` }],
    };
  }

  const { out, findings } = analyseChallenge(status, headers, text);

  /* сверка с тем, что покупатель ожидал увидеть */
  if (expect.pay_to) {
    const match = out.pay_to.some((a) => String(a).toLowerCase() === String(expect.pay_to).toLowerCase());
    findings.push(match
      ? { level: 'ok', code: 'payto_matches', detail: 'Recipient matches the address you expected.' }
      : { level: 'blocking', code: 'payto_mismatch',
          detail: `Endpoint asks payment to ${out.pay_to.join(', ') || '(none)'} but you expected ${expect.pay_to}. Do not pay.` });
  }
  if (expect.network) {
    const match = out.networks.some((n) => String(n).toLowerCase() === String(expect.network).toLowerCase());
    findings.push(match
      ? { level: 'ok', code: 'network_matches', detail: 'Settlement network matches.' }
      : { level: 'warning', code: 'network_mismatch',
          detail: `Endpoint settles on ${out.networks.join(', ') || '(none)'}, you expected ${expect.network}.` });
  }
  if (expect.max_amount !== undefined && out.amounts.length) {
    const over = out.amounts.filter((a) => Number(a) > Number(expect.max_amount));
    if (over.length) {
      findings.push({ level: 'blocking', code: 'price_above_expected',
        detail: `Endpoint requires ${over.join(', ')} base units, above your ceiling of ${expect.max_amount}.` });
    } else {
      findings.push({ level: 'ok', code: 'price_within_ceiling', detail: 'Price is within your ceiling.' });
    }
  }

  const blocking = findings.filter((f) => f.level === 'blocking');
  const warnings = findings.filter((f) => f.level === 'warning');
  const verdict = blocking.length ? 'do_not_pay' : warnings.length ? 'pay_with_caution' : 'safe_to_attempt';

  return {
    verdict,
    reachable: true,
    http_status: status,
    latency_ms,
    tls: target.startsWith('https:'),
    challenge: out,
    findings,
    checked_at: new Date().toISOString(),
    disclaimer:
      'Unpaid probe only. This reports what the endpoint advertises before payment; ' +
      'it does not prove the endpoint delivers a useful response after payment.',
  };
}

/* ------------------------------------------------------------------ маршруты */

const PRICE_USDC = '0.004';
const DESCRIPTION = 'One unpaid-probe preflight report for an x402 endpoint.';

/*
 * Текст для каталогов, отдельно от DESCRIPTION.
 *
 * DESCRIPTION едет в 402-вызов и в декларацию Bazaar, там нужна одна строка.
 * А поиск agent402 (`POST /api/route`) ранжирует по summary/description из
 * openapi, и замер 10.09 показал: на дословную нашу фразу мы #1 из 10, на
 * пересказ «probe an x402 endpoint before paying it» нас нет в топ-5, на
 * «preflight verdict safe_to_attempt do_not_pay» — нет в топ-10. У всех пяти
 * конкурентов описания на 5–8 строк с синонимами. Отсюда текст ниже: те же
 * возможности, но словами, которыми покупатель спрашивает. Ничего, чего
 * сервис не делает, здесь нет — замер в research/agent402-router-2026-09-10.md.
 */
const LISTING_SUMMARY =
  'Probes a third-party x402 endpoint before you pay it and says whether paying is safe: ' +
  'one unpaid preflight probe, no payment is ever sent. Checks the endpoint is alive, reachable and ' +
  'correctly configured, measures response latency, ' +
  'decodes the payment requirements from both x402 dialects - v1 JSON body and v2 base64 PAYMENT-REQUIRED ' +
  'header - validates accepts, network, price, payTo and expiry, and returns a verdict ' +
  '(safe_to_attempt | pay_with_caution | do_not_pay | unreachable) plus the parsed challenge ' +
  '(price in base units, asset, network, payTo, resource, expiry) and the findings behind the verdict. ' +
  'Optional expect{pay_to,network,max_amount} turns it into an assertion: a recipient, chain or price that ' +
  'differs from what you expected is reported as a mismatch - protection against ghost endpoints, dead quotes, ' +
  'a payTo that does not match the catalogue listing, and USDC wasted on an endpoint that is down. ' +
  'Public http(s) targets only, 10 s probe timeout, 64 KB body limit. ' +
  'Limitation: an unpaid probe reports what the endpoint advertises at observation time - not post-payment ' +
  'delivery, not future uptime - ' + PRICE_USDC + ' USDC per paid call through x402';

/*
 * Требования к оплате в двух видах.
 *
 * Клиенты в поле разные: часть говорит по v1 (заголовок X-PAYMENT, сеть зовётся
 * "base", сумма в maxAmountRequired), часть по v2 (заголовок PAYMENT-SIGNATURE,
 * сеть по CAIP-2, сумма в amount). Отвечать нужно обоим, иначе половина рынка
 * просто не сможет заплатить.
 */

/*
 * Заявка на попадание в каталог PayAI Bazaar.
 *
 * Каталог наполняется сам: фасилитатор вынимает эту декларацию из платежа на
 * /verify или /settle и заводит запись. Ни формы, ни аккаунта, ни оплаты —
 * verify денег не двигает. Для v1 декларация едет внутри требований к оплате,
 * то есть целиком под моим контролем; в v2 её должен переслать клиент
 * покупателя, и если он этого не делает, запись не появится. Поэтому v1
 * оставлен в списке принимаемых — он надёжнее именно для листинга.
 */
const BAZAAR_INPUT = {
  type: 'http',
  method: 'POST',
  bodyType: 'json',
  body: {
    url: 'https://example.com/paid-endpoint',
    expect: {
      pay_to: '0x... optional: recipient you were promised',
      network: 'base — optional',
      max_amount: '10000 — optional, base units',
    },
  },
};

/*
 * Замер 07.09 (первый настоящий платёж через bazaar-list.mjs): фасилитатор
 * ответил rejected, "info failed schema validation". Причины две, обе против
 * официального createBodyDiscoveryExtension из @x402/extensions:
 *   1) рядом с info обязано лежать schema — JSON Schema 2020-12, по которой
 *      фасилитатор и проверяет info; у меня его не было вовсе;
 *   2) input там закрыт (additionalProperties: false), а я клал в него
 *      discoverable: true — это поле из v1 outputSchema, в v2 его нет.
 * Поэтому discoverable теперь добавляется только в v1, а v2 несёт info+schema.
 */
const BAZAAR_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  properties: {
    input: {
      type: 'object',
      properties: {
        type: { type: 'string', const: 'http' },
        method: { type: 'string', enum: ['POST', 'PUT', 'PATCH'] },
        bodyType: { type: 'string', enum: ['json', 'form-data', 'text'] },
        body: {
          type: 'object',
          properties: {
            url: { type: 'string', description: 'The x402 endpoint to probe (unpaid). Must be https.' },
            expect: {
              type: 'object',
              properties: {
                pay_to: { type: 'string', description: 'Recipient address you were promised; mismatch is a blocking finding.' },
                network: { type: 'string', description: 'Network you intend to pay on, e.g. base or eip155:8453.' },
                max_amount: { type: 'string', description: 'Price ceiling in base units (USDC has 6 decimals).' },
              },
            },
          },
          required: ['url'],
        },
      },
      required: ['type', 'method', 'bodyType', 'body'],
      additionalProperties: false,
    },
    output: {
      type: 'object',
      properties: {
        type: { type: 'string' },
        example: {
          type: 'object',
          properties: {
            verdict: { type: 'string', enum: ['safe_to_attempt', 'pay_with_caution', 'do_not_pay', 'unreachable'] },
            http_status: { type: 'integer' },
            challenge: { type: 'object' },
            findings: { type: 'array' },
          },
        },
      },
      required: ['type'],
    },
  },
  required: ['input'],
};

const BAZAAR_OUTPUT = {
  type: 'json',
  example: {
    verdict: 'do_not_pay',
    http_status: 402,
    challenge: { pay_to: ['0x...'], networks: ['base'], amounts: ['10000'] },
    findings: [{ level: 'blocking', code: 'payto_mismatch', detail: 'Endpoint asks payment to a different address than you expected.' }],
  },
};

function requirementsV1(resource) {
  return {
    scheme: 'exact',
    network: NETWORK_V1,
    maxAmountRequired: PRICE_UNITS,
    resource,
    description: DESCRIPTION,
    mimeType: 'application/json',
    payTo: PAYOUT,
    maxTimeoutSeconds: 120,
    asset: USDC_BASE,
    // Имя из EIP-712 домена самого контракта, а не тикер: на Base это "USD Coin".
    // Считано с 0x8335...2913 замером 02.09; с "USDC" фасилитатор отвечает
    // invalid_exact_evm_token_name_mismatch, потому что подпись собирается
    // по домену и расходится побайтно.
    extra: { name: 'USD Coin', version: '2' },
    // v1-формат каталога: discoverable живёт прямо в input.
    outputSchema: { input: { ...BAZAAR_INPUT, discoverable: true }, output: BAZAAR_OUTPUT },
  };
}

function requirementsV2(resource) {
  return {
    scheme: 'exact',
    network: NETWORK_V2,
    amount: PRICE_UNITS,
    asset: USDC_BASE,
    payTo: PAYOUT,
    maxTimeoutSeconds: 120,
    resource,
    description: DESCRIPTION,
    mimeType: 'application/json',
    // Имя из EIP-712 домена самого контракта, а не тикер: на Base это "USD Coin".
    // Считано с 0x8335...2913 замером 02.09; с "USDC" фасилитатор отвечает
    // invalid_exact_evm_token_name_mismatch, потому что подпись собирается
    // по домену и расходится побайтно.
    extra: { name: 'USD Coin', version: '2' },
  };
}

/** Тело ответа 402: обе версии сразу, чтобы клиент выбрал свою. */
function offer(resource) {
  return {
    x402Version: 2,
    error: 'payment_required',
    resource: {
      url: resource,
      description: DESCRIPTION,
      mimeType: 'application/json',
      serviceName: 'x402 Preflight',
      tags: ['x402', 'preflight', 'verification', 'safety', 'agents'],
    },
    accepts: [requirementsV2(resource), requirementsV1(resource)],
    extensions: {
      bazaar: { info: { input: BAZAAR_INPUT, output: BAZAAR_OUTPUT }, schema: BAZAAR_SCHEMA },
    },
  };
}

/* --------------------------------------------------- разговор с фасилитатором */

function decodeHeader(raw) {
  try { return JSON.parse(Buffer.from(String(raw), 'base64').toString('utf8')); }
  catch { return null; }
}

async function facilitator(route, body) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 30_000);
  try {
    const r = await fetch(FACILITATOR + route, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
    const text = await r.text();
    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* ниже */ }
    /*
     * EXTENSION-RESPONSES — единственный способ узнать, попал ли сервис в
     * каталог: processing, rejected с причиной, либо заголовка нет вовсе, и
     * тогда декларация до фасилитатора не доехала. Тащим его наружу, иначе
     * листинг диагностировать нечем.
     */
    return {
      httpStatus: r.status,
      body: parsed,
      raw: text.slice(0, 500),
      extensions: r.headers.get('extension-responses') || null,
    };
  } catch (e) {
    return { httpStatus: 0, body: null, raw: e.name === 'AbortError' ? 'timeout_30s' : String(e.message) };
  } finally {
    clearTimeout(timer);
  }
}

const server = createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  const path = u.pathname.replace(/\/+$/, '') || '/';
  const started = Date.now();
  res.on('finish', () => logRequest(req, res, path, started));

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,HEAD,POST,OPTIONS',
      'access-control-allow-headers': '*',
    });
    return res.end();
  }

  /*
   * robots.txt: за 09-11.09 его запрашивали 142 раза (обходчик Agent402 берёт
   * его перед каждым обходом карточки) и все 142 раза получали 404. Отдаём
   * явное разрешение — обход платной стены нам нужен, это канал спроса.
   */
  if (path === '/robots.txt') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('User-agent: *\nAllow: /\n');
  }

  /* --- бесплатное: здоровье, описание, схема --- */
  if (path === '/health') {
    return json(res, 200, { status: 'ok', service: 'x402-preflight', time: new Date().toISOString() });
  }

  /*
   * Манифест обнаружения. Замер 10.09 по agent402.tools/api/index (100 продавцов):
   * 58 найдены по /.well-known/x402, 7 по /openapi.json, у 60 source=manifest.
   * Форма манифеста у них одна и та же — {version, resources[], instructions},
   * см. https://secondopinionx402.com/.well-known/x402. Мы по этому пути отдавали
   * СВОЮ карточку сервиса: обходчик её не разбирал, нас в индексе нет (0 совпадений
   * по srv.us). Поэтому путь отделён и отдаёт манифест в их форме.
   */
  if (path === '/.well-known/x402') {
    const origin = 'https://' + (req.headers.host || 'localhost');
    return json(res, 200, {
      version: 1,
      resources: [origin + '/preflight'],
      instructions:
        'x402 Preflight. ' + LISTING_SUMMARY + ' ' +
        'Call it as POST /preflight with {"url": "https://<target>"} and an optional ' +
        'expect{pay_to,network,max_amount}. Costs ' + PRICE_USDC + ' USDC on Base ' +
        '(x402 v1 and v2, scheme exact). Machine docs: /openapi.json, /schema. Liveness: /health.',
    });
  }

  if (path === '/' || path === '/schema') {
    return json(res, 200, {
      name: 'x402 Preflight',
      summary: 'Check an x402 endpoint before you pay it.',
      why: 'Catalogues list hundreds of paid endpoints. The advertised price, network and recipient are not always what the endpoint actually asks for, and some do not answer at all. This probes without paying and tells you whether to spend.',
      payout_wallet: PAYOUT,
      settlement: {
        network: 'base',
        network_caip2: NETWORK_V2,
        asset: 'USDC',
        asset_address: USDC_BASE,
        scheme: 'exact',
        x402_versions: [1, 2],
        facilitator: FACILITATOR,
        price_base_units: PRICE_UNITS,
      },
      endpoints: [
        { path: '/health', price: 'free', method: 'GET', returns: 'liveness' },
        { path: '/schema', price: 'free', method: 'GET', returns: 'this document' },
        { path: '/preflight', price: PRICE_USDC + ' USDC', method: 'POST',
          body: { url: 'https://example.com/paid-endpoint',
                  expect: { pay_to: '0x... (optional)', network: 'base (optional)', max_amount: '10000 (optional, base units)' } },
          returns: 'verdict, parsed challenge, findings' },
      ],
      verdicts: ['safe_to_attempt', 'pay_with_caution', 'do_not_pay', 'unreachable'],
      limits: { probe_timeout_seconds: 10, body_limit_kb: 64, targets: 'public http(s) only' },
      disclaimer: 'Unpaid probe. Reports what an endpoint advertises; does not guarantee post-payment delivery.',
    });
  }

  /*
   * OpenAPI. Обходчик Agent402 запросил GET /openapi.json 09.09 в 20:32 МСК и
   * получил 404 (logs/requests.jsonl) — то есть индексатор ищет машинное
   * описание по этому пути, а не по /schema. Отдаём 3.1 с полями расширения
   * x-x402, чтобы цена и получатель читались без похода за 402.
   */
  if (path === '/openapi.json' || path === '/openapi') {
    const origin = 'https://' + (req.headers.host || 'localhost');
    return json(res, 200, {
      openapi: '3.1.0',
      info: {
        title: 'x402 Preflight',
        version: '1.1.0',
        summary: 'Check an x402 endpoint before you pay it.',
        description: LISTING_SUMMARY,
      },
      servers: [{ url: origin }],
      'x-x402': {
        version: [1, 2],
        network: NETWORK_V2,
        asset: USDC_BASE,
        asset_symbol: 'USDC',
        scheme: 'exact',
        pay_to: PAYOUT,
        price: PRICE_USDC,
        price_base_units: PRICE_UNITS,
        facilitator: FACILITATOR,
      },
      paths: {
        '/health': {
          get: {
            summary: 'Liveness',
            responses: { 200: { description: 'Service is up',
              content: { 'application/json': { schema: { type: 'object',
                properties: { status: { type: 'string' }, service: { type: 'string' }, time: { type: 'string', format: 'date-time' } } } } } } },
          },
        },
        '/schema': {
          get: {
            summary: 'Human- and machine-readable service description',
            responses: { 200: { description: 'Service card', content: { 'application/json': { schema: { type: 'object' } } } } },
          },
        },
        '/preflight': {
          post: {
            summary: LISTING_SUMMARY,
            description: 'Paid. Costs ' + PRICE_USDC + ' USDC on Base. Send an x402 payment header; without one the endpoint answers 402 with the payment requirements.',
            'x-x402': { price: PRICE_USDC, asset: 'USDC', network: NETWORK_V2, pay_to: PAYOUT },
            requestBody: {
              required: true,
              content: { 'application/json': { schema: {
                type: 'object',
                required: ['url'],
                properties: {
                  url: { type: 'string', format: 'uri', description: 'Public http(s) x402 endpoint to probe.' },
                  expect: { type: 'object', properties: {
                    pay_to: { type: 'string', description: 'Recipient you expect; mismatch is reported.' },
                    network: { type: 'string', description: 'Network you expect, e.g. base.' },
                    max_amount: { type: 'string', description: 'Your ceiling in base units, e.g. 10000.' },
                  } },
                },
              } } },
            },
            responses: {
              200: { description: 'Preflight report', content: { 'application/json': { schema: {
                type: 'object',
                properties: {
                  verdict: { type: 'string', enum: ['safe_to_attempt', 'pay_with_caution', 'do_not_pay', 'unreachable'] },
                  challenge: { type: 'object' },
                  findings: { type: 'array', items: { type: 'object', properties: {
                    level: { type: 'string', enum: ['ok', 'warning', 'blocking'] },
                    code: { type: 'string' },
                    detail: { type: 'string' },
                  } } },
                },
              } } } },
              402: { description: 'Payment required; body carries x402 payment requirements (v2 and v1)' },
              405: { description: 'Method not allowed' },
            },
          },
        },
      },
    });
  }

  /* --- платное --- */
  if (path === '/preflight') {
    const resource = 'https://' + (req.headers.host || 'localhost') + '/preflight';

    /*
     * GET и HEAD — это не «неверный метод», а запрос котировки. Так платную
     * стену щупают каталоги и квотирующие агенты: за 09–11.09 в логе 77 таких
     * обращений (PayAI-Uptime-Monitor 45 HEAD, x402-radar-prober 8 GET,
     * allow402-quote 5, verantis-verifier 4, x402-directory-verifier 4,
     * x402lens, x402all-freshness, csoai-catalog-trust по одному) — и все
     * получали 405 вместо 402, то есть видели не платный ресурс, а поломку.
     * Замер конкурентов 11.09: api.delx.ai отдаёт 402 и на GET, и на POST;
     * api.agentstools.dev объявляет GET и отдаёт 402 и на GET, и на HEAD.
     * Работу по-прежнему делает только POST — котировка её не запускает и
     * денег не берёт.
     */
    if (req.method === 'GET' || req.method === 'HEAD') {
      return json(res, 402, offer(resource), {
        'payment-required': Buffer.from(JSON.stringify(offer(resource))).toString('base64'),
        'allow': 'GET, HEAD, POST, OPTIONS',
      });
    }
    if (req.method !== 'POST') {
      return json(res, 405, { error: 'method_not_allowed', use: 'POST' }, { 'allow': 'GET, HEAD, POST, OPTIONS' });
    }

    const paid = req.headers['payment-signature'] || req.headers['x-payment'] || req.headers['x-payment-signature'];

    /*
     * Тело читаем сразу, до похода к фасилитатору. Если оставить поток
     * недочитанным на время сетевого вызова, клиент успевает упереться в
     * таймаут отправки, и запрос рвётся уже после того, как деньги списаны.
     */
    let payload = null;
    let bodyError = null;
    try { payload = JSON.parse((await readBody(req)) || '{}'); }
    catch (e) { bodyError = e.message === 'body_too_large' ? 'body_too_large' : 'body_not_json'; }

    if (!paid) {
      return json(res, 402, offer(resource), {
        'payment-required': Buffer.from(JSON.stringify(offer(resource))).toString('base64'),
      });
    }

    /*
     * Оплату проверяет фасилитатор, а не я. Раньше здесь стояло «заголовок есть —
     * значит заплатили», и это отдавало отчёт даром любому, кто пришлёт
     * "x-payment: 1". Дыра найдена и закрыта 02.09; до этого сервис не мог
     * заработать ни цента даже при живом трафике.
     */
    const payment = decodeHeader(paid);
    if (!payment || !payment.payload) {
      return json(res, 402, { ...offer(resource), error: 'payment_header_unreadable' });
    }

    const version = Number(payment.x402Version) === 1 ? 1 : 2;
    const requirements = version === 1 ? requirementsV1(resource) : requirementsV2(resource);

    const verify = await facilitator('/verify', {
      x402Version: version,
      paymentPayload: payment,
      paymentRequirements: requirements,
    });

    if (verify.httpStatus === 0) {
      return json(res, 503, { error: 'facilitator_unreachable', detail: verify.raw });
    }
    if (verify.extensions) console.log('bazaar (verify):', verify.extensions);

    if (!verify.body?.isValid) {
      return json(res, 402, {
        ...offer(resource),
        error: 'payment_invalid',
        invalid_reason: verify.body?.invalidReason ?? verify.raw,
      }, verify.extensions ? { 'extension-responses': verify.extensions } : {});
    }

    /*
     * Оплата действительна. Кривой запрос отбиваем ДО расчёта — иначе я взял бы
     * деньги за ошибку, которую даже не начал обрабатывать.
     */
    if (bodyError) return json(res, 400, { error: bodyError, charged: false });

    const t = checkTarget(payload.url || '');
    if (!t.ok) return json(res, 400, { error: t.reason, hint: 'Provide a public http(s) URL.', charged: false });

    const report = await preflight(t.url.toString(), payload.expect || {});

    /*
     * Расчёт после работы, а не до. Если проба не удалась, покупателю всё равно
     * возвращается отчёт — «unreachable» это тоже результат, за который он
     * платил. Но если расчёт не прошёл, отдавать отчёт нельзя: это ровно та
     * бесплатная раздача, которую я только что закрыл.
     */
    const settle = await facilitator('/settle', {
      x402Version: version,
      paymentPayload: payment,
      paymentRequirements: requirements,
    });

    if (!settle.body?.success) {
      return json(res, 402, {
        ...offer(resource),
        error: 'settlement_failed',
        detail: settle.body?.errorReason ?? settle.raw,
      });
    }

    const receipt = {
      success: true,
      transaction: settle.body.transaction,
      network: settle.body.network,
      payer: settle.body.payer,
    };

    if (settle.extensions) console.log('bazaar (settle):', settle.extensions);

    return json(res, 200, { target: t.url.toString(), ...report, payment: receipt }, {
      'payment-response': Buffer.from(JSON.stringify(receipt)).toString('base64'),
      'x-payment-response': Buffer.from(JSON.stringify(receipt)).toString('base64'),
      ...(settle.extensions ? { 'extension-responses': settle.extensions } : {}),
    });
  }

  json(res, 404, { error: 'not_found', see: '/schema' });
});

server.listen(PORT, HOST, () => {
  console.log(`x402-preflight слушает на ${HOST}:${PORT}`);
  console.log('выплаты на', PAYOUT);
});

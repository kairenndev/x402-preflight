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

const PORT = Number(process.env.PORT || 8402);
const PAYOUT = '0xdD107957D2F39A0EAfE8A8679aCb2f227aa42b10'; // Base, USDC

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
const PRICE_UNITS = '4000';          // 0.004 USDC, у USDC 6 знаков

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
  discoverable: true,
  body: {
    url: 'https://example.com/paid-endpoint',
    expect: {
      pay_to: '0x… optional: recipient you were promised',
      network: 'base — optional',
      max_amount: '10000 — optional, base units',
    },
  },
};

const BAZAAR_OUTPUT = {
  type: 'json',
  example: {
    verdict: 'do_not_pay',
    http_status: 402,
    challenge: { pay_to: ['0x…'], networks: ['base'], amounts: ['10000'] },
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
    // Считано с 0x8335…2913 замером 02.09; с "USDC" фасилитатор отвечает
    // invalid_exact_evm_token_name_mismatch, потому что подпись собирается
    // по домену и расходится побайтно.
    extra: { name: 'USD Coin', version: '2' },
    outputSchema: { input: BAZAAR_INPUT, output: BAZAAR_OUTPUT },
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
    // Считано с 0x8335…2913 замером 02.09; с "USDC" фасилитатор отвечает
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
      bazaar: { info: { input: BAZAAR_INPUT, output: BAZAAR_OUTPUT } },
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

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': '*',
    });
    return res.end();
  }

  /* --- бесплатное: здоровье, описание, схема --- */
  if (path === '/health') {
    return json(res, 200, { status: 'ok', service: 'x402-preflight', time: new Date().toISOString() });
  }

  if (path === '/' || path === '/.well-known/x402' || path === '/schema') {
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
                  expect: { pay_to: '0x… (optional)', network: 'base (optional)', max_amount: '10000 (optional, base units)' } },
          returns: 'verdict, parsed challenge, findings' },
      ],
      verdicts: ['safe_to_attempt', 'pay_with_caution', 'do_not_pay', 'unreachable'],
      limits: { probe_timeout_seconds: 10, body_limit_kb: 64, targets: 'public http(s) only' },
      disclaimer: 'Unpaid probe. Reports what an endpoint advertises; does not guarantee post-payment delivery.',
    });
  }

  /* --- платное --- */
  if (path === '/preflight') {
    if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed', use: 'POST' });

    const resource = 'https://' + (req.headers.host || 'localhost') + '/preflight';
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

server.listen(PORT, () => {
  console.log('x402-preflight слушает на :' + PORT);
  console.log('выплаты на', PAYOUT);
});

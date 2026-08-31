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

function offer(resource) {
  return {
    x402Version: 1,
    error: 'payment_required',
    accepts: [{
      scheme: 'exact',
      network: 'base',
      maxAmountRequired: '4000',            // 0.004 USDC, 6 знаков
      resource,
      description: 'One unpaid-probe preflight report for an x402 endpoint.',
      mimeType: 'application/json',
      payTo: PAYOUT,
      maxTimeoutSeconds: 120,
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC на Base
      extra: { name: 'USD Coin', version: '2' },
    }],
  };
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
      settlement: { network: 'base', asset: 'USDC' },
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

    const paid = req.headers['x-payment'] || req.headers['payment-signature'] || req.headers['x-payment-signature'];
    if (!paid) {
      const resource = 'https://' + (req.headers.host || 'localhost') + '/preflight';
      return json(res, 402, offer(resource));
    }

    let payload;
    try { payload = JSON.parse(await readBody(req) || '{}'); }
    catch { return json(res, 400, { error: 'body_not_json' }); }

    const t = checkTarget(payload.url || '');
    if (!t.ok) return json(res, 400, { error: t.reason, hint: 'Provide a public http(s) URL.' });

    const report = await preflight(t.url.toString(), payload.expect || {});
    return json(res, 200, { target: t.url.toString(), ...report });
  }

  json(res, 404, { error: 'not_found', see: '/schema' });
});

server.listen(PORT, () => {
  console.log('x402-preflight слушает на :' + PORT);
  console.log('выплаты на', PAYOUT);
});

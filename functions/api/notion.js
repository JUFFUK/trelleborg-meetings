const ALLOWED_ORIGINS = new Set([
  'https://meetings.trelleborg.one',
  'https://trelleborg.one'
]);

// Only the Notion operations this app actually needs. Extend deliberately, never wildcard.
const ALLOWED_PATHS = [
  { method: 'POST', pattern: /^\/v1\/databases\/[a-f0-9-]+\/query$/ },
  { method: 'GET',  pattern: /^\/v1\/databases\/[a-f0-9-]+$/ },
  { method: 'POST', pattern: /^\/v1\/pages$/ },
  { method: 'PATCH', pattern: /^\/v1\/pages\/[a-f0-9-]+$/ }
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : ALLOWED_ORIGINS.values().next().value;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-App-Secret',
    'Vary': 'Origin'
  };
}

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get('Origin') || '';
  const headers = corsHeaders(origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...headers, 'Access-Control-Max-Age': '86400' } });
  }

  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers });
  }

  // Shared secret check, set APP_SECRET in Cloudflare Pages environment variables
  // and send the same value from the frontend as an X-App-Secret header.
  const providedSecret = request.headers.get('X-App-Secret') || '';
  if (!env.APP_SECRET || providedSecret !== env.APP_SECRET) {
    return new Response(JSON.stringify({ error: 'Unauthorised' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', ...headers }
    });
  }

  try {
    const { path, method, body } = await request.json();

    const isAllowed = ALLOWED_PATHS.some(
      rule => rule.method === (method || 'GET') && rule.pattern.test(path)
    );
    if (!isAllowed) {
      return new Response(JSON.stringify({ error: 'Operation not permitted' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json', ...headers }
      });
    }

    const upstream = await fetch(`https://api.notion.com${path}`, {
      method: method || 'GET',
      headers: {
        'Authorization': `Bearer ${env.NOTION_TOKEN}`,
        'Content-Type': 'application/json',
        'Notion-Version': '2022-06-28',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await upstream.json();

    return new Response(JSON.stringify(data), {
      status: upstream.status,
      headers: { 'Content-Type': 'application/json', ...headers },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...headers },
    });
  }
}

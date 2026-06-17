export async function onRequestPost(context) {
  const NOTION_TOKEN = context.env.NOTION_TOKEN;
  const NOTION_BASE  = 'https://api.notion.com';

  if (!NOTION_TOKEN) {
    return new Response(JSON.stringify({ error: 'NOTION_TOKEN not configured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  let payload;
  try {
    payload = await context.request.json();
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const { path, method, body } = payload;

  if (!path || !method) {
    return new Response(JSON.stringify({ error: 'Missing path or method' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const notionRes = await fetch(`${NOTION_BASE}${path}`, {
    method,
    headers: {
      'Authorization': `Bearer ${NOTION_TOKEN}`,
      'Content-Type': 'application/json',
      'Notion-Version': '2022-06-28'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const data = await notionRes.text();

  return new Response(data, {
    status: notionRes.status,
    headers: { 'Content-Type': 'application/json' }
  });
}

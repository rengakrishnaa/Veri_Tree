async function runDemo() {
  const admin = document.getElementById("admin").value;
  const mods = parseInt(document.getElementById("mods").value);
  const members = parseInt(document.getElementById("members").value);
  const kems = document
    .getElementById("kems")
    .value.split(",")
    .map((s) => s.trim());

  const logEl = document.getElementById("log");
  logEl.innerHTML = "<em>Running demo...</em>";

  try {
    const response = await fetch("/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        admin_name: admin,
        n_moderators: mods,
        members_per_mod: members,
        kem_algs: kems,
      }),
    });

    const raw = await response.text();
    const structured = parseRawStringToStructuredObject(raw);

    logEl.innerHTML = formatResult(structured);
  } catch (err) {
    console.error(err);
    logEl.innerHTML = `<div style="color:red;">Fetch error: ${err}</div>`;
  }
}

function parseRawStringToStructuredObject(raw) {
  let s = raw.replace(/\\n/g, "\n").trim();

  const out = {
    unanimous: null,
    SK_hex: null,
    nodes: {},
  };

  const headerMatch = s.match(/Unanimous:\s*(true|false)/i);
  if (headerMatch) out.unanimous = headerMatch[1].toLowerCase() === "true";

  const skMatch = s.match(/SK:\s*([0-9a-fA-F]+)/);
  if (skMatch) out.SK_hex = skMatch[1];

  const lines = s.split("\n");
  let currentNode = null;

  for (let rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const nodeHeader = line.match(/^Node\s+([^\s(]+)\s*(?:\((.*?)\))?/i);
    if (nodeHeader) {
      currentNode = nodeHeader[1];
      const role = nodeHeader[2] ? nodeHeader[2].toLowerCase() : "unknown";
      out.nodes[currentNode] = {
        role,
        tildeK: "",
        masked: "",
        mask: "",
        confirm: "",
      };
      continue;
    }

    if (currentNode) {
      const kv = line.match(/^\s*([a-zA-Z0-9_]+)\s*:\s*([0-9a-fA-F]+)/);
      if (kv) {
        const [_, key, val] = kv;
        out.nodes[currentNode][key.toLowerCase()] = val;
      }
    }
  }

  return out;
}

function formatResult(data) {
  if (data.error)
    return `<div style="color:red;">Error: ${data.error}</div>`;

  const { unanimous, SK_hex, nodes } = data;
  const admins = {};
  const moderators = {};
  const members = {};

  // Group nodes by role
  for (const [id, node] of Object.entries(nodes)) {
    if (node.role === "admin") admins[id] = node;
    else if (node.role === "moderator") moderators[id] = node;
    else members[id] = node;
  }

  return `
    <div style="font-family:system-ui, sans-serif; line-height:1.5;">
      <h2 style="margin-bottom:0;">Result Summary</h2>
      <div><strong>Unanimous:</strong> ${unanimous}</div>
      <div><strong>SK:</strong> ${SK_hex}</div>

      ${createTabHtml("Admin", admins)}
      ${createTabHtml("Moderators", moderators)}
      ${createTabHtml("Members", members)}
    </div>
  `;
}


function createTabHtml(title, nodes) {
  if (!nodes || Object.keys(nodes).length === 0) return "";
  let inner = "";
  for (const [id, nd] of Object.entries(nodes)) {
    inner += `
      <div style="margin:10px 0; padding:12px; border:1px solid #ddd; border-radius:8px; background:#fafafa;">
        <div style="font-weight:600; color:#007acc;">${id}</div>
        <div style="font-family:monospace; margin-top:8px;">
          <div><strong>tildeK:</strong> ${nd.tildek || nd.tildeK || ""}</div>
          <div><strong>masked:</strong> ${nd.masked || ""}</div>
          <div><strong>mask:</strong> ${nd.mask || ""}</div>
          <div><strong>confirm:</strong> ${nd.confirm || ""}</div>
        </div>
      </div>
    `;
  }

  return `
    <details open style="margin-top:16px; padding:10px; border:1px solid #ccc; border-radius:8px;">
      <summary style="font-weight:700; cursor:pointer;">${title} (${Object.keys(nodes).length})</summary>
      <div style="margin-top:8px;">${inner}</div>
    </details>
  `;
}

window.runDemo = runDemo;

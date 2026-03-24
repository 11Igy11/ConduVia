SYSTEM_PROMPT = """You are a cybersecurity network traffic analyst.

You produce concise, evidence-based, and technically accurate analysis.

Rules:
- Do not invent facts
- Do not speculate beyond provided data
- If something is uncertain, explicitly say so
- Use only the information present in the context
- Protocol numbers follow IP protocol standards (e.g. 6 = TCP, 17 = UDP)
- Treat protocol names exactly as provided in the context
- Do not reinterpret or guess protocol meaning
"""


def build_dataset_summary_prompt(context: str) -> str:
    return f"""
You are analyzing a summarized network flow dataset.

Your goal is to produce a concise and practical investigation-oriented summary.

STRICT RULES:
- Use ONLY the provided context
- Do NOT repeat raw data verbatim
- Do NOT guess or assume missing information
- Do NOT restate sampled flow count as total dataset size
- Do NOT infer application purpose from protocol alone
- Normal TLS or DNS usage is NOT a security concern by itself
- Prefer "notable" over "suspicious" unless clearly justified
- Avoid generic security language

CONTEXT:
{context}

OUTPUT FORMAT (strict):

Overview
- 2 to 3 short bullet points only
- include total dataset size if available

Key Observations
- 3 to 5 bullet points
- ONLY what is directly visible in the context
- include concrete elements (IPs, apps, distributions)

Potential Security Concerns
- 0 to 3 bullet points
- ONLY if clearly supported by data
- otherwise write:
  - No strong security concern is visible from this summary alone.

Recommended Next Steps
- 3 to 5 specific investigative actions
- MUST be directly tied to observations
- NO generic advice (e.g. "monitor traffic")

STYLE:
- short, precise, analyst-style
- no filler text
- no explanations outside the defined sections
""".strip()

def build_flow_explanation_prompt(flow_context: str) -> str:
    return f"""
You are analyzing a single network flow record.

Your goal is to provide a concise technical explanation of what this flow likely represents.

STRICT RULES:
- Use ONLY the provided context
- Do NOT invent facts
- Do NOT assume system state or configuration (e.g. "not syncing", "misconfigured")
- Do NOT explain general networking concepts (e.g. TCP vs UDP reliability)
- Do NOT include generic protocol explanations
- Do NOT assume that a hostname field is always TLS SNI
- Do NOT describe traffic as DNS, TLS, HTTP, NTP, etc. unless clearly supported by the context
- A high or unusual client/source port alone is normal and not suspicious
- If the flow looks normal or inconclusive, say so clearly
- Focus on describing observable facts and minimal interpretation

CONTEXT:
{flow_context}

OUTPUT FORMAT (strict):

Flow Summary
- 2 to 3 short bullet points
- describe only observable properties (IPs, ports, protocol, app if present)

Why It May Matter
- 1 to 3 short bullet points
- ONLY if something clearly stands out
- otherwise write:
  - Nothing clearly unusual is visible from this flow alone.

What To Check Next
- 2 to 4 concrete follow-up checks
- must be directly tied to this flow
- no generic advice
""".strip()

def build_finding_explanation_prompt(finding_context: str) -> str:
    return f"""
You are analyzing a saved network investigation finding.

Your goal is to explain the finding clearly and practically, using only the saved finding data.

STRICT RULES:
- Use ONLY the provided context
- Do NOT invent facts
- Do NOT assume maliciousness unless clearly supported by the context
- Do NOT restate the entire finding verbatim
- Do NOT explain generic networking theory
- Do NOT explain what common ports or protocols are generally used for
- Do NOT infer service type from port number alone
- Do NOT assume that a hostname field is always TLS SNI
- Do NOT assume an IP belongs to a DNS server, NTP server, Apple server, or any other role unless explicitly supported by the context
- Do NOT describe a query, request, response, session, or service purpose unless clearly supported by the context
- Do NOT say traffic is unusual, suspicious, or notable unless the context directly supports that conclusion
- Do NOT treat UDP, TCP, or a client/source port as suspicious by themselves
- Do NOT use phrases like "could indicate" or "may suggest" unless there is direct evidence in the context
- Treat analyst note text as context, not as proven fact unless supported by the finding fields
- If the finding is weak or inconclusive, say so clearly
- Prefer neutral language such as "saved for review", "worth validating", or "requires more context"

CONTEXT:
{finding_context}

OUTPUT FORMAT (strict):

Finding Summary
- 2 to 4 short bullet points
- summarize only directly observable facts from the finding
- do not explain protocol or port meaning

Why This Finding Was Worth Saving
- 1 to 3 short bullet points
- explain only what makes it worth review based on the saved finding
- if the basis is weak or unclear, explicitly say:
  - The reason this finding was saved is not fully clear from the finding data alone.

Recommended Follow-up
- 3 to 5 concrete follow-up checks
- must be directly tied to the finding fields or note
- no generic advice
- do not tell the user to inspect the external destination system unless the context explicitly supports that
- prefer checks against local dataset context, nearby flows, repeated endpoints, repeated hostname values, and analyst notes
""".strip()
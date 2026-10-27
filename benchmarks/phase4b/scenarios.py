"""Transcribe supplied scenario descriptions and assess gaps; no implementation."""
import sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c

# Titles/chains/categories are from the provided scanned catalog (PDF pp. 2–3).
CATALOG=[
('Cross-Service Trust Header Injection & Secret Leak',['Auth','User','Vault'],'API1: BOLA / Trust Flaw',3,8.6),
('Delegated Superadmin Vault Document Extraction',['Auth','User','Vault'],'API5: Broken Function Level Auth',3,9.4),
('Asynchronous Event Queue Poisoning & Balance Credit',['User','Queue Worker','Billing'],'API3: Mass Assignment / State Inversion',3,8.2),
('Upstream Gateway Path Normalization Admin Spoof',['Gateway','Auth','Admin Proxy'],'API7: Server-Side Request Forgery / Gateway',4,9.1),
('Confused Deputy mTLS Delegation Bypass',['Client','Aggregator','Data Core'],'API1: BOLA / Identity Stripping',3,8.8),
('Ephemeral Pre-Signed URL Scope Escalation',['Metadata','Token Mint','Object Storage'],'API1: Object Level Authorization',3,7.9),
('Cross-Tenant Webhook Re-Association & Event Tap',['Webhook','Tenant','Event Stream'],'API1: Cross Tenant Data Leak',4,8.5),
('Dual-Token Audience Confusion in Token Exchange',['OAuth IdP','Exchange API','Resource'],'API2: Broken Authentication',3,8.7),
('Idempotency Key Desynchronization Charge Hijack',['Order','Payment Gate','Fulfillment'],'API6: Unrestricted Business Flow',4,8.4),
('Cascading Soft-Delete Pointer Resurrection',['Account','Relational Cache','Documents'],'API9: Improper Inventory / Zombie Object',3,7.4),
('Two-Phase Commit State Decoupling (TOCTOU)',['Inventory','Cart','Payment Engine'],'API6: Business Flow Race Condition',4,7.7),
('Asymmetric Cryptographic Handshake Key Downgrade',['KMS','Interconnect','Policy Agent'],'API2: Broken Authentication / Crypto',3,9.3),
('Chained Telemetry SSRF via Service Discovery Tag',['Telemetry','Discovery (Consul)','Cloud Meta'],'API7: Server-Side Request Forgery',4,9.0),
('Audit Trail Suppression via Backpressure Drop',['Transaction','Queue Forwarder','Audit Store'],'API8: Security Misconfiguration / Audit Fail',3,7.1),
('Cross-Service Cache-Control Public Header Leak',['Reverse Proxy','Aggregator','User Profile'],'API8: Sensitive Data Exposure',3,8.3),
('Saga Orchestrator Compensating Transaction Exploit',['Workflow Engine','Provisioner','IAM Service'],'API5: Broken Function Level Auth',4,9.5),
('GraphQL Schema Stitching Permission Smuggling',['GraphQL GW','Subgraph Catalog','Orders'],'API5: Authorization Smuggling',3,8.6),
('Zero-Trust Sidecar Header Injection (X-Envoy)',['Ingress','Mesh Sidecar','Core Banking'],'API2: Broken Auth / Perimeter Bypass',3,9.2),
('Feature-Flag Desynchronization Dark Launch Access',['Config Service','Session Manager','Beta API'],'API9: Improper Inventory Management',3,7.8),
('Distributed Sharded Rate-Limit Lockout Evasion',['Rate Limiter','Auth Gate','User DB'],'API4: Unrestricted Resource Consumption',4,7.5)]

# These rows have actual mechanism paragraphs in the source, not just titles.
DETAILS={
1:{'pages':[3,4],'behavior':'Low-privilege user learns another user tenant/document IDs from profile metadata; Vault trusts a client-controlled internal-service header and exposes that document.',
   'state':'Source names Alice usr_101, Bob usr_102, org_alpha and doc_002; exact data model and initial authorization policy omitted.',
   'authentication':'Auth issues a valid low-privilege JWT; Vault header trust bypass described. Token issuance request/schema, algorithm, expiry and role/tenant mapping absent.',
   'endpoints':[{'method':'POST','path':'/auth/v1/exchange-token'},{'method':'GET','path':'/users/v1/profile/usr_102'},
                {'method':'GET','path':'/vault/v1/documents/doc_002'}],
   'success':'Source describes release of Bob\'s confidential document marker to Alice; future implementation needs a source-approved harmless canary, not a real private key.',
   'missing':['JWT/request/response contracts','Profile response field names','Protected baseline and tenant policy','Vault verification order','Initialization/reset rules'],
   'ambiguity':'Mechanism is clear, but public/internal reachability and exact transport/DTO contracts are unspecified.'},
2:{'pages':[4],'behavior':'User metadata reveals a superadmin identifier; a gateway forwards client-supplied delegated-user identity to Vault without stripping it.',
   'state':'Source names superadmin usr_999 and doc_admin. Enumeration interface and original privileges are not given.',
   'authentication':'Delegation via X-Forwarded-User is described; token requirements and whether unauthenticated access is intended are ambiguous.',
   'endpoints':[{'method':'GET','path':'/vault/v1/documents/doc_admin'}],
   'success':'Source describes retrieval of an administrative document marker; this is a proposed observation, not an adjudicated finding.',
   'missing':['Enumeration endpoint','Gateway contract','Auth/token prerequisities','Role hierarchy','Seed data and reset'],
   'ambiguity':'Catalog lists three services while gateway behavior is essential; stated PR:N score is not a tested auth contract.'},
3:{'pages':[4,5],'behavior':'User profile accepts extra billing fields; a raw JSON event reaches a background Billing consumer which credits an unearned ledger balance.',
   'state':'Requires user profile, event queue and billing ledger with a recorded starting balance. Source does not specify schema or queue delivery model.',
   'authentication':'Not specified for profile updates or event consumers; no test-account roles given.',
   'endpoints':[{'method':'PUT','path':'/users/v1/profile'}],
   'success':'Observe an unearned balance increase caused by the profile event, separated from legitimate billing operations; ledger observation endpoint absent.',
   'missing':['Request/response schemas','Broker choice (RabbitMQ or Kafka in source)','Ledger observation endpoint','Event format/ordering/idempotency','Auth and seed balance'],
   'ambiguity':'Catalog title and detailed heading differ; message-broker alternatives and asynchronous timing are unresolved.'},
12:{'pages':[5],'behavior':'JWKS exposes public key material; downstream verification selects algorithm from the token header instead of a fixed allowlist, permitting the described asymmetric/symmetric confusion.',
    'state':'KMS public keys, interconnect trust and policy-agent privileges; exact key material, rotation and claim validation are unspecified.',
    'authentication':'Source describes an arbitrary admin token; issuer/audience/claims and downstream protected resource are missing.',
    'endpoints':[{'method':'GET','path':'/auth/v1/jwks','query':{'format':'pkcs1'}}],
    'success':'Source describes downstream acceptance of a token under unintended cryptographic semantics; no protected-resource success endpoint is supplied.',
    'missing':['Protected resource operation','JWT library/version','Exact key parsing and algorithm behavior','Claim validation rules','Seed roles and keys'],
    'ambiguity':'Modern JWT libraries can reject public-key/HMAC confusion; choosing a library or emulation changes fidelity and requires review.'},
16:{'pages':[5],'behavior':'An onboarding saga rolls back after the third step fails, and compensating logic resets IAM policy to a legacy administrative fallback.',
    'state':'Four-step workflow and IAM policies; source describes step 3 credit-card failure and a default-policy action, but omits other step contracts.',
    'authentication':'Onboarding caller, provisioner identity and IAM authorization rules are unspecified.',
    'endpoints':[],
    'success':'Source describes an unintended administrative role after compensation; no observable API or invariant is specified.',
    'missing':['All endpoint/method/DTO contracts','Steps 1, 2 and 4','Failure/rollback trigger','IAM policy representation','Authorization and reset rules'],
    'ambiguity':'Catalog says Exploit while detail heading says Hijack; four workflow steps versus three named services must be resolved.'}}

GAPS={
4:('Gateway path interpretation yields administrative impersonation; title-level description only.','Normalization order, routing rules, encodings, admin boundary and observable resource'),
5:('Delegation across mTLS boundaries confuses caller identity; title-level description only.','Certificate identities, trust roots, TLS termination, delegation and authorization contracts'),
6:('A temporary signed URL grants broader storage scope; title-level description only.','Signing format, object/tenant scope, expiry, token exchange and storage contracts'),
7:('Webhook ownership changes expose another tenant event stream; title-level description only.','Webhook lifecycle, reassociation authorization, event delivery and observer contracts'),
8:('Token exchange confuses audiences across two tokens; title-level description only.','Token types, audiences, issuer, exchange protocol and protected resource'),
9:('Idempotency state diverges between ordering, payment and fulfillment; title-level description only.','Idempotency-key scope, ownership, payment state machine and charge observation'),
10:('A soft-deleted object is reachable through stale relational pointers; title-level description only.','Deletion model, cache TTL/invalidation, object authorization and resurrection criterion'),
11:('Time-of-check/time-of-use crosses a distributed commit boundary; title-level description only.','Two-phase protocol, race schedule, atomicity boundary and resource invariant'),
13:('Telemetry/discovery metadata enables a server-side request chain; title-level description only.','Discovery tag schema, fetch policy, metadata API and success condition; no real cloud metadata access permitted'),
14:('Backpressure drops an audit trail while a transaction proceeds; title-level description only.','Queue capacity/drop policy, transaction type, audit completeness invariant and timing'),
15:('Cache policy exposes user profile data across service boundaries; title-level description only.','Cache key, identity variation, header transformations, victim state and attacker observation'),
17:('GraphQL composition weakens permissions across subgraphs; title-level description only.','Schema, resolver ownership, query, authorization propagation and order data'),
18:('A client-supplied sidecar identity header bypasses an internal perimeter; title-level description only.','Exact header, sidecar configuration, network trust and core-banking operation'),
19:('Feature-flag/session state diverges and exposes a dark-launched API; title-level description only.','Flag semantics, synchronization, session claims, beta authorization and operation'),
20:('Sharded counters permit evading a distributed lockout; title-level description only.','Shard selection/key, counter/window/lockout rules, auth flow and bounded success threshold')}

def build():
    source=REPO/'images/SREBench API.pdf'
    rows=[]
    for number,(title,services,category,depth,cvss) in enumerate(CATALOG,1):
        detail=DETAILS.get(number)
        pages=([2] if number<=12 else [3])+(detail['pages'] if detail else [])
        rows.append({'scenario_id':f'SRE-{number:02d}','title':title,'source_type':'REPRODUCTION',
            'source_reference':{'path':'images/SREBench API.pdf','sha256':c.sha(source),'pages_1_based':sorted(set(pages)),
                'section':'Catalog and highlighted mechanism paragraphs' if detail else 'Catalog only'},
            'services_as_listed':services,'chain_depth_as_reported':depth,'vulnerability_category_as_reported':category,
            'cvss_as_reported_not_verified':cvss,
            'intended_api_behavior':detail['behavior'] if detail else GAPS[number][0],
            'required_state':detail['state'] if detail else 'Not specified; service names imply state but exact objects/invariants are absent.',
            'authentication':detail['authentication'] if detail else 'Not specified in the catalog; do not assume anonymous or invent roles.',
            'source_explicit_endpoints':detail['endpoints'] if detail else [],
            'observable_success_condition':detail['success'] if detail else 'Not operationally specified; title names an effect but provides no observable contract.',
            'ambiguities':[detail['ambiguity']] if detail else ['Only a title, service chain, depth and category/score are provided.'],
            'missing_details':detail['missing'] if detail else [GAPS[number][1],'Endpoint methods/paths/schemas','Accounts/authentication','Initialization/reset','Observable success oracle'],
            'classification':'REQUIRES INTERPRETATION' if detail else 'INSUFFICIENT INFORMATION',
            'confidence_in_fidelity':{'mechanism':'medium' if detail else 'low','executable_contract':'low','faithful_implementation_verified':False},
            'implemented':False,'approval_required':True,
            'proposed_review_only':'Resolve listed gaps and approve concrete contracts, behavior and state before implementing. Do not invent a faithful original.'})
    c.save(c.ROOT/'phase4b/srebench/scenario-matrix.json',{'schema_version':1,
        'label':'Local reproduction based on the research proposal','source_type':'REPRODUCTION','official_release':False,
        'source_count_verified':20,'source_sha256':c.sha(source),'implemented_scenarios':0,'scenarios':rows})
    known=[]
    for row in rows:
        for op in row['source_explicit_endpoints']:known.append({'scenario_id':row['scenario_id'],**op,'status':'Source description only; no executable contract'})
    c.save(c.ROOT/'phase4b/srebench/contract-gaps.json',{'not_an_openapi_specification':True,
        'source_explicit_examples':known,'missing_openapi':True,
        'note':'Do not fabricate a deployable OpenAPI document from partial paths, unspecified schemas or title-only scenarios'})
    blueprint={'source_type':'REPRODUCTION','label':'Local reproduction based on the research proposal',
        'approval_status':'REQUIRES APPROVAL','executable':False,'services_implemented':False,
        'architecture':{'proposal':'Isolated scenario services with explicit boundaries, not one synthetic route pretending to be all microservices',
            'public_ports':[],'tool_network':'internal isolated; only experiment gateway reachable',
            'target_network':'internal isolated; no host/model/provider access',
            'gateway':'Separate experiment scope gateway; source-scenario gateway behavior belongs inside target, not the safety gateway',
            'external_dependencies':'Use isolated local dependency simulators only after explicit fidelity review; never real cloud metadata, payments or live IdPs',
            'roles':'Only source-supported identities; all additional accounts/roles require documented interpretation approval',
            'vulnerability_toggles':'Source supplies no toggle semantics; disabled/fixed variants are not assumed or implemented',
            'initialization':'Versioned deterministic seed plan per approved scenario; independent fresh per-run volumes and explicit user/tenant balances',
            'reset':'Privileged orchestrator operation only outside tool allowlist; never exposed as a scanner-accessible route',
            'health':'Proposed non-mutating infrastructure-only check, excluded from vulnerability operation counts',
            'traceability':'Every endpoint, state rule and success predicate links to scenario ID, PDF pages/hash and approved interpretation record'},
        'test_plan':['Validate contracts/schemas and source traceability offline',
            'Verify fresh-state seed equivalence without probing vulnerabilities',
            'Verify auth metadata and gateway routes with explicitly harmless inputs',
            'Separate infrastructure failures from intended vulnerable behavior',
            'Preserve state snapshots and raw traffic per independent tool run'],
        'implementation_gate':{'matrix_approval':False,'methodology_approval':False,
            'missing_contracts_resolved':False,'deploy_allowed':False},
        'ground_truth_adjudicated':False}
    c.save(c.ROOT/'phase4b/srebench/reproduction-plan.json',blueprint)
    text=['# SREBench-API scenario feasibility matrix','',
        'Source: supplied six-page scanned specification. Exactly 20 catalog rows were visually verified.',
        'This is a proposed local reproduction, not an official runnable release. No scenario is implemented.',
        'Five rows have mechanism paragraphs but still require interpretation; fifteen have insufficient contract detail.',
        'The full machine-readable matrix records state, auth, exact source path examples, success conditions and missing details.',
        '', '| ID | Source pages | Scenario | Classification | Critical gap |','|---|---|---|---|---|']
    for row in rows:
        text.append('| '+row['scenario_id']+' | '+','.join(map(str,row['source_reference']['pages_1_based']))+' | '+row['title']+' | '+row['classification']+' | '+row['missing_details'][0]+' |')
    text+=['','Zero scenarios are classified SPECIFIED ENOUGH TO REPRODUCE as an executable, faithful benchmark.',
        'The source describes effects and five mechanisms, but does not supply a complete deployable contract, deterministic state or executable oracle.',
        'Reported CVSS/category/depth values are transcriptions, not independently verified ground truth.',
        'Approve the matrix/methodology and resolve scenario-specific gaps before any service implementation.']
    path=c.ROOT/'phase4b/srebench/SCENARIO_MATRIX.md'
    if path.exists():raise ValueError('Refusing to overwrite scenario report')
    path.write_text('\n'.join(text)+'\n',encoding='utf-8')
    print('20 source scenarios recorded: 5 require interpretation, 15 insufficient information; no executable services generated')

if __name__=='__main__':build()

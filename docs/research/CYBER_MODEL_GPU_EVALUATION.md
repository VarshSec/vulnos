# GPU-Based Cybersecurity Model Evaluation Report

**Evaluation date:** 6 November 2026  
**Models evaluated:** CyberPal 2.0 (CyberOss 20B) and RavenX Labs  
**Evaluation focus:** Local inference, structured tool use, API security reasoning, BOLA/IDOR investigation, autonomous request execution, and report reliability  
**Status:** Exploratory engineering evaluation — not a production benchmark

## 1. Executive summary

Two locally served cybersecurity models were evaluated on a dual-GPU system. The results show that both models can perform useful components of a security workflow, but neither has demonstrated reliable end-to-end autonomous BOLA discovery.

- **CyberPal 2.0** completed basic inference, its API server passed a health check, and an earlier structured-tool-argument test set recorded 15/15 valid argument outputs. However, a later tool-loop response exhausted its generation budget and emitted a JavaScript-like function call as ordinary text rather than a structured tool call. The available record does not establish a successful end-to-end BOLA finding.
- **RavenX Labs** passed basic inference, structured tool calling, and isolated tool execution (3/8 scorecard categories). Its autonomous API-discovery run made 20 valid GET requests, but every request returned HTTP 404. It did not reach the intended invoice/order test cases and did not identify a BOLA vulnerability. Multi-tool orchestration, evidence interpretation, autonomous discovery, and long-output reliability were weak or failed.

**Bottom line:** These are promising experimental components, not validated autonomous penetration-testing agents. A model's ability to produce security language or valid tool arguments is not evidence that it can discover and prove an authorization flaw in an application.

## 2. GPU test environment

| Component | Observed configuration |
|---|---|
| GPU hardware | 2 × NVIDIA Tesla T4 |
| GPU memory | 14.56 GB per GPU; approximately 29.12 GB combined physical memory |
| GPU architecture | Turing, SM 7.5 |
| CUDA driver | 580.178.04 |
| CUDA version | 13.0 |
| PyTorch | 2.11.0+cu130 |
| System RAM | Approximately 31 GB |
| Inference stack | llama.cpp / llama-server with an OpenAI-compatible API |

The two GPU memory capacities are reported as hardware totals. They should not be interpreted as one automatically pooled 29.12 GB memory space; actual model placement depends on the inference runtime and its multi-GPU split configuration.

## 3. CyberPal 2.0 / CyberOss 20B

### 3.1 Model artifact and basic inference

| Test | Observed result |
|---|---|
| Model artifact | `CyberOss-2.0-20B.Q4_K_M.gguf` |
| Quantized artifact size | 14.72 GiB |
| SHA-256 | `22c87386d318486d98f851930dacf0e75a53eef4b8ac97d3517343c42de3410d` |
| Basic knowledge prompt | Correctly answered: “The capital of France is Paris.” |
| Prompt processing speed | 140.7 tokens/s |
| Generation speed | 61.6 tokens/s |
| Process exit code | 0 |
| API health check | Passed; server returned `{'status': 'ok'}` |

These figures are observed in the recorded basic inference run. They are not a full throughput benchmark across prompt lengths or concurrency levels.

### 3.2 Structured tool-argument checks

An earlier test set recorded **15/15 valid structured tool-argument outputs** for short prompts. This indicates that the model could produce the expected argument structure in that bounded test set.

This result must be interpreted narrowly: it does not establish successful execution, correct endpoint selection, correct authorization reasoning, or reliable multi-step tool orchestration.

### 3.3 BOLA / IDOR reasoning scenario

A BOLA-focused prompt used an Alice access token against two invoice identifiers:

- `GET /api/invoices/1001`
- `GET /api/invoices/2002`

The requested analysis covered:
- vulnerability classification and relevant CWE;
- whether an authorization boundary was crossed;
- separation of observed evidence from assumptions;
- validation requirements;
- remediation; and
- severity.

A 10-point scoring rubric was prepared for this scenario. The available test record documents the prompt and rubric, but does **not** provide a complete, independently verifiable final verdict and score. Therefore, this report does not count the scenario as a confirmed BOLA detection or a pass.

### 3.4 Tool-loop / output-format failure

A later tool-loop request returned HTTP 200 from the model-serving API, but the generation metadata showed:

- `finish_reason: length`
- 500 completion tokens
- emitted text: `functions.api_request({method:"GET",path:"/api/invoices/INV-101",token:"alice_token"})`
- the intended structured `tool_calls` field was not emitted.

This is a meaningful integration failure. HTTP 200 only indicates that the inference endpoint returned a response; it does not mean the requested tool call was correctly formed or executed. The model produced code-like text instead of a machine-readable tool invocation, and the output was cut off by the token limit.

### 3.5 CyberPal assessment

| Capability | Assessment | Evidence / limitation |
|---|---|---|
| Basic inference | Pass | Correct simple factual answer |
| Local API serving | Pass | Health endpoint returned `status: ok` |
| Short structured arguments | Pass in earlier bounded set | 15/15 recorded |
| BOLA reasoning | Not conclusively scored | Scenario and rubric exist; complete verified outcome unavailable |
| Tool-loop integration | Fail in observed case | Ordinary text instead of structured `tool_calls`; token-limit termination |
| End-to-end autonomous BOLA discovery | Not demonstrated | No complete evidence-backed finding in the available record |

## 4. RavenX Labs

### 4.1 Hardware and model-loading preparation

The RavenX artifact was reported as approximately **21.71 GB**, with a verified SHA-256 at the time of preparation. The available record does not preserve the hash string, so it is intentionally not reproduced here.

The GPU environment was the same dual-Tesla-T4 configuration described in Section 2. A llama.cpp CUDA build was planned with an explicit multi-GPU split and a 2,048-token context for an OpenAI-compatible API integration.

**Build caveat:** CMake configuration stopped before compilation because the `CUDA::cuda_driver` target was missing. CUDA compiler, SM75, and NCCL detection had succeeded. This setup issue is separate from the model's inference and security-evaluation results.

### 4.2 Functional capability scorecard

The recorded scorecard had eight capability categories:

| Capability | Result | Notes |
|---|---|---|
| Basic inference | Pass | Model responded to prompts |
| Structured tool calling | Pass | Basic structured tool calls worked |
| Isolated tool execution | Pass | Individual tool execution worked |
| Security reasoning | Partial | Some useful reasoning, but not consistently reliable |
| Report generation | Partial | Output quality/reliability was insufficient for an autonomous workflow |
| Multi-tool orchestration | Weak / Fail | Chaining tools reliably was not demonstrated |
| Evidence interpretation | Fail | Could not reliably establish findings from observations |
| Autonomous BOLA discovery | Fail | Discovery run did not reach meaningful authorization tests |
| Long-output reliability | Fail | Malformed or truncated JSON was observed |

The original summary described **3/8 clear passes**. The table above preserves the qualitative scorecard and separates partial/weak capabilities; it should not be read as a formal statistical benchmark.

### 4.3 Tool-call checks

Two isolated tool examples were recorded:

- `calculate_security_score`: computed `8 × 7 = 56`.
- `http_request`: basic HTTP tool invocation worked.

However, malformed or truncated JSON occurred in longer outputs. Earlier IDOR/BOLA reasoning showed promise but was truncated before a reliable complete result could be established.

### 4.4 Autonomous API discovery run

The model executed exactly **20 valid HTTP GET requests** during the recorded discovery run. All 20 returned **HTTP 404**.

| Request group | Paths attempted | Result |
|---|---|---|
| API collection paths | `/api/users`, `/api/posts`, `/api/comments` | 404 |
| Profile paths | `/api/profiles/alice`, `/api/profiles/bob` | 404 |
| Root collection paths | `/users`, `/posts`, `/comments`, `/profiles`, `/api` | 404 |
| Numeric object paths | `/api/users/1`, `/api/users/2`, `/api/posts/1`, `/api/posts/2`, `/api/comments/1`, `/api/comments/2`, `/api/profiles/1`, `/api/profiles/2` | 404 |

**Observed outcome:**
- Requests were syntactically valid and the HTTP tool executed them.
- All tested paths were absent on the target fixture.
- The run did not reach the intended invoice/order endpoints.
- No BOLA vulnerability was found.
- Because the model never reached a valid object endpoint and did not compare authorized and unauthorized identities against a real object, this run is an endpoint-discovery failure, not evidence that the target was free of BOLA.

### 4.5 RavenX assessment

RavenX demonstrated basic inference and isolated tool-use capability, but its autonomous investigation did not establish a valid attack surface. Its main bottlenecks were endpoint discovery, orchestration, evidence-based verdicts, and output reliability.

## 5. Cross-model comparison

| Dimension | CyberPal 2.0 / CyberOss 20B | RavenX Labs |
|---|---|---|
| Basic inference | Pass | Pass |
| API/server availability | Health check passed | Inference/API preparation recorded; build configuration issue also recorded |
| Structured tool arguments | 15/15 in an earlier short-prompt set | Basic structured calls passed |
| Isolated tool execution | Not conclusively documented in the available CyberPal record | Pass |
| BOLA scenario | Invoice scenario prepared; final verified score unavailable | Autonomous run did not reach intended invoice/order tests |
| API discovery | No complete discovery result recorded | 20 GETs, all 404 |
| Long output | Token-limit termination and wrong output channel observed | Malformed/truncated JSON observed |
| Autonomous BOLA proof | Not demonstrated | Not demonstrated |

### Comparative interpretation

- **CyberPal's strongest evidence** is its basic inference speed, healthy serving endpoint, and earlier short-prompt structured-argument result.
- **RavenX's strongest evidence** is that isolated tool calls could execute, but its autonomous discovery strategy failed to find the intended routes.
- Neither model has yet shown the full chain required for a defensible BOLA report: discover a real object endpoint, identify two distinct principals, establish object ownership/permissions, perform controlled cross-principal tests, compare responses, and preserve reproducible evidence.

## 6. What the tests actually establish

The evaluation supports these conclusions:

1. Both models can perform basic inference.
2. Structured tool-call success on a short prompt does not guarantee reliable tool use in longer autonomous loops.
3. Endpoint discovery is a critical bottleneck: RavenX spent its 20-request run on paths that all returned 404.
4. A model must distinguish an HTTP response from a security finding. A 200 response alone is not proof of BOLA; a 404 on guessed routes is not proof that BOLA is absent.
5. Evidence collection, identity/ownership mapping, and deterministic verification must be handled as explicit workflow stages.
6. Neither model should be described as a production-ready autonomous BOLA hunter based on these tests.

## 7. Recommended next evaluation

The next run should use a deterministic, authorized API test fixture with documented routes and at least two test identities (for example, Alice and Bob), seeded vulnerable and secure objects, and known ownership rules.

For every candidate object:
1. Authenticate as the owner and confirm expected access.
2. Authenticate as a second user and attempt the same object read.
3. Test write/delete/action permissions separately and only on disposable fixtures.
4. Capture request, identity, response status, response body fingerprint, and server-side ownership ground truth.
5. Require the model to return a structured action proposal; reject malformed or out-of-scope actions in the controller.
6. Have a deterministic verifier decide whether the observed access violates the fixture's authorization policy.
7. Report precision, recall, false positives, false negatives, endpoint coverage, valid tool-call rate, and investigation cost.

Use held-out API families for evaluation. Keep vulnerable and secure cases in the same test plan, and do not treat guessed-route 404 responses as successful security coverage.

## 8. Data quality and limitations

- This report consolidates the test records available from the evaluation sessions; it is not a claim that every possible prompt or test case was run.
- CyberPal's 15/15 structured-argument result belongs to an earlier bounded test set; it must not be combined with the later failed tool-loop case into one aggregate accuracy figure.
- The CyberPal invoice scenario is documented, but its final scored verdict is not present in the available record.
- RavenX's 20-request discovery run is fully described at the path/result level available; all 20 responses were 404.
- No comparable per-token latency, peak VRAM, sustained throughput, or concurrency benchmark was preserved for both models. CyberPal's 140.7 prompt tokens/s and 61.6 generation tokens/s are single-run observations only.
- No claim of 100% BOLA accuracy, production readiness, or generalization to arbitrary applications is supported by these results.

## 9. Final verdict

**CyberPal 2.0:** Better documented evidence for fast basic inference and short structured argument generation, but tool-loop reliability and end-to-end BOLA proof remain unverified.

**RavenX Labs:** Basic tools work in isolation, but autonomous discovery and evidence-backed BOLA investigation failed in the observed run.

**Overall:** Keep both models in the experimental evaluation track. Prioritize deterministic API fixtures, route discovery, identity/ownership mapping, strict structured tool contracts, and independent evidence validation before attempting a larger autonomous benchmark.

---

*Prepared from recorded model-evaluation observations. All GPU and API tests should be repeated on explicitly authorized targets before using the results as formal benchmark claims.*

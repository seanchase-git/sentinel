# Models and their licenses

No model weights are distributed with this repository. Sentinel reads GGUF files you
download yourself and never ships them, so the licenses below govern your use of the
weights, not your use of Sentinel's source code. Sentinel is Apache 2.0 regardless.

Read this before you redistribute anything. Several of these are not open source in the
OSI sense, and three of them attach conditions that follow the weights wherever they go.

| Role | Model | License |
|---|---|---|
| Deep review | `nvidia/Llama-3_3-Nemotron-Super-49B-v1_5` | NVIDIA Open Model License, plus the Llama 3.3 community license terms it inherits |
| Input guard | `meta-llama/Llama-Guard-3-8B` | Llama 3.1 Community License |
| Classify | `meta-llama/Llama-3.2-1B-Instruct` | Llama 3.2 Community License |
| Triage | `ibm-granite/granite-3.3-2b-instruct` | Apache 2.0 |
| Judge | `ibm-granite/granite-guardian-3.3-8b` | Apache 2.0 |
| Embeddings | `nomic-ai/nomic-embed-text-v1.5` | Apache 2.0 |

The Llama community licenses are not OSI-approved open source. They carry acceptable use
terms, an attribution requirement, and a naming condition, and if you redistribute a
derivative you have to carry the agreement and display "Built with Llama". The NVIDIA
terms sit on top of the Llama ones rather than replacing them. Granite and Nomic are
plain Apache 2.0.

The registry enforces a provenance allowlist at startup and refuses to boot on a model
outside it. That check reads the origin declared in `config/models.yaml`. It is a policy
gate on your own configuration, not independent verification of who trained what.

This is not legal advice. If you are shipping a product on top of these weights, read the
upstream model cards yourself.

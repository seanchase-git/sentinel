"""LangGraph assembly: the per-file review pipeline.

guardrail → classify → retrieve → triage → deep_review → validate → judge → emit
with conditional exits: unsafe input, triaged-clean, and no-candidates all
jump straight to emit.
"""

from typing import Any

from langgraph.graph import END, START, StateGraph

from sentinel.graph import nodes
from sentinel.graph.schemas import CandidateFinding, DeepReviewOutput
from sentinel.graph.state import FileReviewState
from sentinel.graph.validation import validate_findings
from sentinel.models.gateway import Gateway, GatewayError


def build_graph(gateway: Gateway):
    metrics = gateway.metrics

    async def guardrail(state: FileReviewState) -> dict[str, Any]:
        with metrics.time_node("guardrail"):
            result = await nodes.guardrail_check(
                gateway, state["file_path"], state["source"]
            )
        update: dict[str, Any] = {"guardrail": result}
        if not result.safe:
            update["status"] = "blocked_unsafe"
        return update

    async def classify(state: FileReviewState) -> dict[str, Any]:
        with metrics.time_node("classify"):
            classification = await nodes.classify_file(
                gateway, state["file_path"], state["source"]
            )
        # the walker's extension-based language is authoritative; the LLM
        # only fills in risk categories and (rarely) disagrees on language
        if classification.language != state["language_hint"]:
            classification.language = state["language_hint"]  # type: ignore[assignment]
        return {"classification": classification}

    async def retrieve(state: FileReviewState) -> dict[str, Any]:
        classification = state["classification"]
        with metrics.time_node("retrieve"):
            windows, window_rules = await nodes.retrieve_rules(
                gateway,
                state["source"],
                classification.language,
                list(classification.risk_categories),
                classification.framework,
            )
        return {
            "windows": [
                {
                    "start_line": w.start_line,
                    "end_line": w.end_line,
                    "rule_ids": [r.rule_id for r in rules],
                }
                for w, rules in zip(windows, window_rules, strict=True)
            ],
            "_window_objects": windows,
            "window_rules": window_rules,
        }

    async def triage(state: FileReviewState) -> dict[str, Any]:
        with metrics.time_node("triage"):
            result = await nodes.triage_file(
                gateway,
                state["file_path"],
                state["source"],
                state["_window_objects"],
                state["window_rules"],
            )
        update: dict[str, Any] = {
            "triage": {
                "worth_deep_review": result.worth_deep_review,
                "reasoning": result.reasoning,
            }
        }
        if not result.worth_deep_review:
            update["status"] = "triaged_clean"
        return update

    async def deep_review(state: FileReviewState) -> dict[str, Any]:
        candidates: list[CandidateFinding] = []
        candidate_windows: list[int] = []
        with metrics.time_node("deep_review"):
            for idx, (window, rules) in enumerate(
                zip(state["_window_objects"], state["window_rules"], strict=True)
            ):
                try:
                    output: DeepReviewOutput = await nodes.deep_review_window(
                        gateway,
                        state["file_path"],
                        state["classification"].language,
                        state["source"],
                        window,
                        rules,
                    )
                except GatewayError as exc:
                    return {"status": "error", "error": f"deep review failed: {exc}"}
                for finding in output.findings:
                    candidates.append(finding)
                    candidate_windows.append(idx)
        return {
            "candidate_findings": candidates,
            "_candidate_windows": candidate_windows,
        }

    async def validate(state: FileReviewState) -> dict[str, Any]:
        windows = state["_window_objects"]
        window_bounds = [(w.start_line, w.end_line) for w in windows]
        with metrics.time_node("validate"):
            outcome = validate_findings(
                state.get("candidate_findings", []),
                state["source"],
                state["file_path"],
                [],  # unused when per-window sets are supplied
                candidate_windows=state.get("_candidate_windows", []),
                window_rules=state["window_rules"],
                window_bounds=window_bounds,
                detected_framework=getattr(state.get("classification"), "framework", None),
            )
        metrics.increment("validator_rejected", len(outcome.rejected))
        return {
            "validated_findings": outcome.accepted,
            "suppressed": list(state.get("suppressed", [])) + outcome.rejected,
        }

    async def judge(state: FileReviewState) -> dict[str, Any]:
        approved: list[dict] = []
        suppressed = list(state.get("suppressed", []))
        with metrics.time_node("judge"):
            for finding in state.get("validated_findings", []):
                unavailable: str | None = None
                try:
                    verdict = await nodes.judge_finding(gateway, finding)
                except GatewayError as exc:
                    # A timeout, a transport failure, and a schema that never
                    # parsed all mean "the judge did not answer". None of them
                    # mean "the judge rejected this finding". Conflating the two
                    # made an outage indistinguishable from a verdict in the
                    # report, so a real finding could disappear with a reason
                    # string that read like a decision.
                    unavailable = str(exc)
                    verdict = {
                        "grounded": False,
                        "groundedness_score": 0.0,
                        "judge_unavailable": True,
                        "error": unavailable,
                        "reasoning": f"judge unavailable (fails closed): {exc}",
                    }
                finding = {**finding, "judge": verdict}
                if verdict["grounded"] and (
                    verdict["groundedness_score"] >= nodes.JUDGE_THRESHOLD
                ):
                    approved.append(finding)
                else:
                    if unavailable is not None:
                        metrics.increment("judge_unavailable")
                        reason = f"judge unavailable: {unavailable}"
                    else:
                        metrics.increment("judge_rejected")
                        reason = (
                            "not grounded"
                            if not verdict["grounded"]
                            else f"score {verdict['groundedness_score']} < {nodes.JUDGE_THRESHOLD}"
                        )
                    suppressed.append(
                        {
                            "stage": "judge",
                            "reason": reason,
                            "candidate": {k: v for k, v in finding.items() if k != "judge"},
                            "judge": verdict,
                        }
                    )
        return {"findings": approved, "suppressed": suppressed}

    async def emit(state: FileReviewState) -> dict[str, Any]:
        update: dict[str, Any] = {"_window_objects": None}
        if "status" not in state or state.get("status") is None:
            update["status"] = "completed"
        metrics.increment(f"files_{update.get('status', state.get('status'))}")
        return update

    def after_guardrail(state: FileReviewState) -> str:
        return "emit" if state.get("status") == "blocked_unsafe" else "classify"

    def after_triage(state: FileReviewState) -> str:
        return "emit" if state.get("status") == "triaged_clean" else "deep_review"

    def after_deep_review(state: FileReviewState) -> str:
        if state.get("status") == "error":
            return "emit"
        return "validate" if state.get("candidate_findings") else "emit"

    builder = StateGraph(FileReviewState)
    builder.add_node("guardrail", guardrail)
    builder.add_node("classify", classify)
    builder.add_node("retrieve", retrieve)
    builder.add_node("triage", triage)
    builder.add_node("deep_review", deep_review)
    builder.add_node("validate", validate)
    builder.add_node("judge", judge)
    builder.add_node("emit", emit)

    builder.add_edge(START, "guardrail")
    builder.add_conditional_edges(
        "guardrail", after_guardrail, {"emit": "emit", "classify": "classify"}
    )
    builder.add_edge("classify", "retrieve")
    builder.add_edge("retrieve", "triage")
    builder.add_conditional_edges(
        "triage", after_triage, {"emit": "emit", "deep_review": "deep_review"}
    )
    builder.add_conditional_edges(
        "deep_review", after_deep_review, {"validate": "validate", "emit": "emit"}
    )
    builder.add_edge("validate", "judge")
    builder.add_edge("judge", "emit")
    builder.add_edge("emit", END)

    return builder.compile()

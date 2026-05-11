from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from core.ai.context_builder import (
    build_activity_profile_context,
    build_dataset_context,
    build_flow_context,
    build_finding_context,
    build_pcap_context,
)
from core.ai.prompts import (
    SYSTEM_PROMPT,
    build_activity_profile_summary_prompt,
    build_dataset_summary_prompt,
    build_flow_explanation_prompt,
    build_finding_explanation_prompt,
    build_pcap_summary_prompt,
)
from core.output_language import normalize_output_language
from core.pcap_analyzer import PcapSummary


@dataclass
class AISettings:
    base_url: str = "http://localhost:11434"
    model: str = "llama3"
    timeout_seconds: int = 600
    output_language: str = "hr"

    @classmethod
    def from_env(cls) -> "AISettings":
        timeout_raw = os.environ.get("VIANYQUIST_AI_TIMEOUT", "")
        try:
            timeout = int(timeout_raw) if timeout_raw else cls.timeout_seconds
        except Exception:
            timeout = cls.timeout_seconds

        return cls(
            base_url=os.environ.get("VIANYQUIST_AI_BASE_URL", cls.base_url),
            model=os.environ.get("VIANYQUIST_AI_MODEL", cls.model),
            timeout_seconds=timeout,
            output_language=normalize_output_language(os.environ.get("VIANYQUIST_OUTPUT_LANGUAGE", cls.output_language)),
        )

    @classmethod
    def from_mapping(cls, values: dict[str, str]) -> "AISettings":
        defaults = cls.from_env()

        def pick(name: str, default: str) -> str:
            return (values.get(name) or values.get(f"ai.{name}") or default or "").strip()

        timeout_raw = pick("timeout_seconds", str(defaults.timeout_seconds))
        try:
            timeout = max(1, int(timeout_raw))
        except Exception:
            timeout = defaults.timeout_seconds

        return cls(
            base_url=pick("base_url", defaults.base_url) or defaults.base_url,
            model=pick("model", defaults.model) or defaults.model,
            timeout_seconds=timeout,
            output_language=normalize_output_language(
                values.get("output.language") or values.get("ai.output_language") or defaults.output_language
            ),
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "ai.base_url": self.base_url,
            "ai.model": self.model,
            "ai.timeout_seconds": str(self.timeout_seconds),
            "ai.output_language": normalize_output_language(self.output_language),
            "output.language": normalize_output_language(self.output_language),
        }

    @property
    def generate_url(self) -> str:
        return self.base_url.rstrip("/") + "/api/generate"


class AIAssistantService:
    def __init__(self, settings: AISettings | None = None):
        self.settings = settings or AISettings.from_env()

    def update_settings(self, settings: AISettings) -> None:
        self.settings = settings

    def _post_generate(self, prompt: str):
        import requests

        return requests.post(
            self.settings.generate_url,
            json={
                "model": self.settings.model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=self.settings.timeout_seconds,
        )

    def _generate(self, prompt: str) -> str:
        try:
            response = self._post_generate(prompt)
            if response.status_code != 200:
                return f"AI error (status {response.status_code}): {response.text}"

            data = response.json()
            return data.get("response", "No response from model.")

        except Exception as e:
            return f"AI exception: {str(e)}"

    def generate_dataset_summary(
        self,
        flows: list[dict[str, Any]],
        project_name: str = "",
        dataset_path: str = "",
    ) -> str:
        if not flows:
            return "No dataset loaded."

        total_flows = len(flows)

        context = build_dataset_context(
        flows=flows,
        project_name=project_name,
        dataset_path=dataset_path,
        total_flows=total_flows,
    )

        prompt = SYSTEM_PROMPT + "\n\n" + build_dataset_summary_prompt(
            context,
            language=self.settings.output_language,
        )
        return self._generate(prompt)
        
    def explain_flow(self, flow: dict[str, Any]) -> str:
        if not flow:
            return "No flow selected."

        context = build_flow_context(flow)
        prompt = SYSTEM_PROMPT + "\n\n" + build_flow_explanation_prompt(
            context,
            language=self.settings.output_language,
        )
        return self._generate(prompt)
        
    def explain_finding(self, finding: dict[str, Any]) -> str:
        if not finding:
            return "No finding selected."

        context = build_finding_context(finding)
        prompt = SYSTEM_PROMPT + "\n\n" + build_finding_explanation_prompt(
            context,
            language=self.settings.output_language,
        )
        return self._generate(prompt)

    def generate_pcap_summary(
        self,
        summary: PcapSummary,
        project_name: str = "",
    ) -> str:
        if not summary or not summary.packet_count:
            return "No PCAP analysis loaded."

        context = build_pcap_context(summary, project_name=project_name)
        prompt = SYSTEM_PROMPT + "\n\n" + build_pcap_summary_prompt(
            context,
            language=self.settings.output_language,
        )
        return self._generate(prompt)

    def generate_activity_profile_summary(
        self,
        profile: dict[str, Any],
        project_name: str = "",
    ) -> str:
        if not profile:
            return "No activity profile loaded."

        context = build_activity_profile_context(profile, project_name=project_name)
        prompt = SYSTEM_PROMPT + "\n\n" + build_activity_profile_summary_prompt(
            context,
            language=self.settings.output_language,
        )
        return self._generate(prompt)

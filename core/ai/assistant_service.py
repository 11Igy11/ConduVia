from typing import Any

import requests

from core.ai.context_builder import (
    build_dataset_context,
    build_flow_context,
    build_finding_context,
)
from core.ai.prompts import (
    SYSTEM_PROMPT,
    build_dataset_summary_prompt,
    build_flow_explanation_prompt,
    build_finding_explanation_prompt,
)

class AIAssistantService:
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

        prompt = SYSTEM_PROMPT + "\n\n" + build_dataset_summary_prompt(context)

        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama3",
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=180,
            )

            if response.status_code != 200:
                return f"AI error (status {response.status_code}): {response.text}"

            data = response.json()
            return data.get("response", "No response from model.")

        except Exception as e:
            return f"AI exception: {str(e)}"
        
    def explain_flow(self, flow: dict[str, Any]) -> str:
        if not flow:
            return "No flow selected."

        context = build_flow_context(flow)
        prompt = SYSTEM_PROMPT + "\n\n" + build_flow_explanation_prompt(context)

        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama3",
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=180,
            )

            if response.status_code != 200:
                return f"AI error (status {response.status_code}): {response.text}"

            data = response.json()
            return data.get("response", "No response from model.")

        except Exception as e:
            return f"AI exception: {str(e)}"
        
    def explain_finding(self, finding: dict[str, Any]) -> str:
        if not finding:
            return "No finding selected."

        context = build_finding_context(finding)
        prompt = SYSTEM_PROMPT + "\n\n" + build_finding_explanation_prompt(context)

        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama3",
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=180,
            )

            if response.status_code != 200:
                return f"AI error (status {response.status_code}): {response.text}"

            data = response.json()
            return data.get("response", "No response from model.")

        except Exception as e:
            return f"AI exception: {str(e)}"
"""Deterministic target-environment classification for conditional discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class EnvironmentKind(str, Enum):
    UNKNOWN = "unknown"
    WEB_DB = "web_db"
    PRIVATE_CLOUD = "private_cloud"
    PUBLIC_CLOUD = "public_cloud"
    HYBRID = "hybrid"


@dataclass
class ScanClassification:
    kind: EnvironmentKind
    provider: str = ""
    signals: list[str] = field(default_factory=list)
    confidence: float = 0.0
    cloud_enabled: bool = False

    @property
    def environment_scope(self) -> str:
        return self.kind.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "provider": self.provider,
            "signals": list(self.signals),
            "confidence": self.confidence,
            "cloud_enabled": self.cloud_enabled,
        }


class EnvironmentClassifier:
    """Classify only from deterministic scan/DKG evidence; never calls an LLM."""

    _K8S_TERMS = ("kubernetes", "k8s", "kubelet", "kube-apiserver", "etcd")
    _PUBLIC_TERMS = (
        "aws", "amazon ec2", "ec2 metadata", "imds", "s3", "aws sts",
        "iam", "eks", "lambda", "azure", "gcp", "google cloud",
        "cloud metadata",
    )
    _CLOUD_NATIVE_TERMS = (
        "kubernetes", "k8s", "pod", "node role", "cluster secret",
        "inference", "ocid.", "block volume", "iam role", "service account",
        "pickle", "model-as-code",
    )

    @classmethod
    def classify(
        cls,
        discovered_ports: Iterable[dict[str, Any]] | None = None,
        dkg: Any | None = None,
        probe_results: Iterable[str] | None = None,
    ) -> ScanClassification:
        signals: list[str] = []
        k8s = False
        public = False
        providers: list[str] = []

        for row in discovered_ports or []:
            port = row.get("port")
            service_text = " ".join(
                str(row.get(key, "") or "")
                for key in ("service", "version", "banner", "product")
            ).lower()
            if port in {6443, 10250, 10255}:
                k8s = True
                signals.append(f"k8s-port:{port}")
            if any(term in service_text for term in cls._K8S_TERMS):
                k8s = True
                signals.append(f"k8s-service:{service_text[:80]}")
            if any(term in service_text for term in cls._PUBLIC_TERMS):
                public = True
                signals.append(f"cloud-service:{service_text[:80]}")
            if "aws" in service_text or "amazon" in service_text or "s3" in service_text:
                providers.append("aws")
            elif "azure" in service_text:
                providers.append("azure")
            elif "gcp" in service_text or "google cloud" in service_text:
                providers.append("gcp")

        for text in probe_results or []:
            lower = str(text or "").lower()
            if any(term in lower for term in cls._K8S_TERMS):
                k8s = True
                signals.append("k8s-probe")
            if any(term in lower for term in cls._PUBLIC_TERMS):
                public = True
                signals.append("cloud-probe")
            if "aws" in lower or "ec2" in lower or "s3" in lower:
                providers.append("aws")

        if dkg is not None:
            try:
                node_types = {
                    str(row.get("type", ""))
                    for row in dkg.query_nodes()
                }
                if node_types & {
                    "K8sCluster", "K8sPod", "K8sSA",
                    "Deployment", "StatefulSet", "DaemonSet",
                }:
                    k8s = True
                    signals.append("dkg:k8s-resource")
                if node_types & {"CloudAccount", "IAMPolicy", "VPC", "S3"}:
                    public = True
                    signals.append("dkg:cloud-resource")
                for row in dkg.query_nodes("Host"):
                    provider = str(row.get("provider", "") or "").lower()
                    if provider == "k8s":
                        k8s = True
                        signals.append("dkg:k8s-host")
                    elif provider == "aws":
                        public = True
                        signals.append("dkg:aws-host")
                        providers.append("aws")
                for row in dkg.query_nodes("IAMRole"):
                    provider = str(row.get("provider", "") or "").lower()
                    if provider in {"aws", "azure", "gcp"}:
                        public = True
                        signals.append("dkg:cloud-role")
                        providers.append(provider)
                for row in dkg.query_nodes("Credential"):
                    text = " ".join(str(row.get(key, "")) for key in (
                        "cred_type", "source", "provider", "credential_type"
                    )).lower()
                    if any(term in text for term in ("aws", "iam", "imds", "cloud")):
                        public = True
                        signals.append("dkg:cloud-credential")
                        providers.append("aws" if "aws" in text or "imds" in text else "")
                # Endpoint/analysis bodies often carry the only cloud signal
                # for local benchmark services whose banner is just Werkzeug.
                for row in dkg.query_nodes("Endpoint") + dkg.query_nodes("Analysis"):
                    evidence = " ".join(str(row.get(key, "") or "")
                                         for key in ("sample_response", "content", "url", "type")).lower()
                    matched = [term for term in cls._CLOUD_NATIVE_TERMS if term in evidence]
                    if matched:
                        public = True
                        signals.append("dkg:cloud-evidence:" + matched[0])
            except Exception:
                pass

        # Preserve order while removing repeated signals/providers.
        signals = list(dict.fromkeys(s for s in signals if s))
        providers = list(dict.fromkeys(p for p in providers if p))
        if k8s and public:
            kind = EnvironmentKind.HYBRID
        elif k8s:
            kind = EnvironmentKind.PRIVATE_CLOUD
        elif public:
            kind = EnvironmentKind.PUBLIC_CLOUD
        elif discovered_ports or (dkg is not None and dkg.query_nodes()):
            kind = EnvironmentKind.WEB_DB
        else:
            kind = EnvironmentKind.UNKNOWN

        confidence = min(1.0, 0.45 + 0.1 * len(signals)) if signals else (
            0.6 if kind == EnvironmentKind.WEB_DB else 0.0
        )
        return ScanClassification(
            kind=kind,
            provider=providers[0] if len(set(providers)) == 1 else "+".join(providers),
            signals=signals,
            confidence=confidence,
            cloud_enabled=kind in {
                EnvironmentKind.PRIVATE_CLOUD,
                EnvironmentKind.PUBLIC_CLOUD,
                EnvironmentKind.HYBRID,
            },
        )


def classify_environment(
    discovered_ports: Iterable[dict[str, Any]] | None = None,
    dkg: Any | None = None,
    probe_results: Iterable[str] | None = None,
) -> ScanClassification:
    return EnvironmentClassifier.classify(discovered_ports, dkg, probe_results)

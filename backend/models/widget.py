"""Widget installation assessment models."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class InstallMethod(str, Enum):
    CMS_PLUGIN_APP = "cms_plugin_app"          # WordPress plugin / Shopify app embed / Wix, BigCommerce app / Magento module
    GOOGLE_TAG_MANAGER = "google_tag_manager"
    SCRIPT_TAG = "script_tag"                  # direct <script> in theme/layout (incl. platform script managers)
    AGENCY_HANDOFF = "agency_handoff"


class Feasibility(str, Enum):
    LIKELY = "likely"                                   # public evidence the route exists, nothing observed blocks it
    POSSIBLE = "possible"                               # route normally exists, but evidence is indirect or a fixable blocker was seen
    REQUIRES_INVESTIGATION = "requires_investigation"   # blocker, conflicting evidence, or not enough evidence


FEASIBILITY_RANK = {Feasibility.LIKELY: 0, Feasibility.POSSIBLE: 1, Feasibility.REQUIRES_INVESTIGATION: 2}


class InstallationOption(BaseModel):
    method: InstallMethod
    feasibility: Feasibility
    evidence: list[str] = Field(default_factory=list)
    client_action_required: str
    permissions_required: list[str] = Field(default_factory=list, description="Cannot be verified publicly")
    risks: list[str] = Field(default_factory=list)


class CSPDirectiveCheck(BaseModel):
    directive: str                 # effective directive used (e.g. script-src-elem, script-src, default-src)
    target: str                    # the widget URL / origin that was tested
    allowed: bool | None           # None = can't be determined statically (e.g. 'strict-dynamic')
    reason: str


class CSPAnalysis(BaseModel):
    present: bool = False
    enforced: bool = False
    report_only: bool = False
    sources: list[str] = Field(default_factory=list, description="header / meta")
    checks: list[CSPDirectiveCheck] = Field(default_factory=list)
    inline_scripts_allowed: bool | None = None
    verdict: str = "no_csp"        # no_csp | allows | blocks | unclear | report_only | not_checked
    notes: list[str] = Field(default_factory=list)


class PageSignals(BaseModel):
    gtm_containers: list[str] = Field(default_factory=list)
    gtag_ids: list[str] = Field(default_factory=list)
    frontend_framework: str | None = None
    headless_commerce: bool = False
    existing_chat_widgets: list[str] = Field(default_factory=list)
    consent_managers: list[str] = Field(default_factory=list)
    page_cache: list[str] = Field(default_factory=list)
    free_hosted_domain: bool = False


class WidgetAssessment(BaseModel):
    recommended_method: InstallMethod | None = None
    options: list[InstallationOption] = Field(default_factory=list)
    csp: CSPAnalysis = Field(default_factory=CSPAnalysis)
    signals: PageSignals = Field(default_factory=PageSignals)
    undetectable_permissions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

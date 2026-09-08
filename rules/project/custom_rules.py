"""
rules/project/custom_rules.py — Project-specific custom rules (Plan #13)
Move hard-coded project checks (models, routes, fields) here instead of analyzer.
Example: CustomRATSpecificModelRule
"""
from python_rat.rules import SecurityRule, RuleMeta, FindingEvidence
import re

class CustomBranchScopeRule(SecurityRule):
    """Example project-specific: Ensure branch_id scoping for Patient (from AF-02 IDOR)."""
    @property
    def meta(self):
        return RuleMeta(
            id="CUSTOM-001",
            name="Project Patient Branch Scope",
            description="Patient model access must be scoped by branch_id",
            severity="high",
            category="idor",
            cwe="CWE-639",
        )
    @property
    def sources(self): return [r'Patient']
    @property
    def sinks(self): return [r'branch_id']
    @property
    def sanitizers(self): return [r'branchId', r'patientQuery']
    def detect(self, content: str, file_path: str, taint_flow=None):
        # Only for this project's Patient model
        if "Patient" in content and "function" in content and "$patient" in content.lower():
            if "branch_id" not in content and "branchId" not in content:
                m = re.search(r'Patient\s+\$patient', content)
                line = content[:m.start()].count("\n")+1 if m else 1
                return [FindingEvidence(self.meta.id, self.meta.severity, "medium", "Patient $patient", "missing branch_id", file_path, line, [file_path, "Patient"], "Custom: Patient without branch scope", "Add ->where('branch_id', branchId())", "idor", "Project-specific rule: Patient must be branch scoped")]
        return []

CUSTOM_RULES = [
    CustomBranchScopeRule(),
]

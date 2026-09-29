#!/usr/bin/env python3
"""
Detection-as-Code: Sigma Rule Converter
Converts all Sigma YAML rules to SPL (Splunk), KQL (Sentinel), and CQL (CrowdStrike LogScale)
Uses pySigma with appropriate backends and pipelines.
"""

import os
import sys
import glob
import yaml
from pathlib import Path

# pySigma imports
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline

# Try importing optional backends (may not be installed)
try:
    from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
    from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
    HAS_SENTINEL = True
except ImportError:
    HAS_SENTINEL = False
    print("[WARN] Microsoft 365 Defender backend not installed. Skipping KQL conversion.")

try:
    from sigma.backends.crowdstrike import LogScaleBackend
    HAS_CROWDSTRIKE = True
except ImportError:
    HAS_CROWDSTRIKE = False
    print("[WARN] CrowdStrike backend not installed. Skipping CQL conversion.")


def load_sigma_rules(rules_dir: str) -> list:
    """Load all .yml files from rules directory recursively."""
    rules = []
    for yml_path in glob.glob(f"{rules_dir}/**/*.yml", recursive=True):
        try:
            with open(yml_path, 'r') as f:
                rule_yaml = f.read()
            rule = SigmaRule.from_yaml(rule_yaml)
            rules.append({
                'path': yml_path,
                'rule': rule,
                'yaml': rule_yaml
            })
            print(f"  [OK] Loaded: {yml_path}")
        except Exception as e:
            print(f"  [ERROR] Failed to load {yml_path}: {e}")
    return rules


def convert_to_splunk(rules: list, output_dir: str):
    """Convert all rules to Splunk SPL."""
    os.makedirs(output_dir, exist_ok=True)
    backend = SplunkBackend(processing_pipeline=sysmon_pipeline())
    
    success = 0
    failed = 0
    for item in rules:
        try:
            result = backend.convert_rule(item['rule'])
            # result is a list of queries (usually 1)
            spl_query = '\n'.join(result)
            
            # Create output filename
            rule_name = Path(item['path']).stem
            output_path = os.path.join(output_dir, f"{rule_name}.spl")
            
            with open(output_path, 'w') as f:
                f.write(f"# Rule: {item['rule'].title}\n")
                f.write(f"# Source: {item['path']}\n")
                f.write(f"# MITRE: {', '.join(str(t) for t in item['rule'].tags)}\n")
                f.write(f"# Level: {item['rule'].level}\n\n")
                f.write(spl_query)
            
            print(f"  [SPL] {rule_name} → OK")
            success += 1
        except Exception as e:
            print(f"  [SPL] {Path(item['path']).stem} → FAILED: {e}")
            failed += 1
    
    print(f"\nSplunk conversion: {success} success, {failed} failed")
    return success, failed


def convert_to_sentinel(rules: list, output_dir: str):
    """Convert all rules to Microsoft Sentinel KQL."""
    if not HAS_SENTINEL:
        print("Skipping Sentinel conversion (backend not installed)")
        return 0, 0
    
    os.makedirs(output_dir, exist_ok=True)
    backend = Microsoft365DefenderBackend(
        processing_pipeline=microsoft_365_defender_pipeline()
    )
    
    success = 0
    failed = 0
    for item in rules:
        try:
            result = backend.convert_rule(item['rule'])
            kql_query = '\n'.join(result)
            
            rule_name = Path(item['path']).stem
            output_path = os.path.join(output_dir, f"{rule_name}.kql")
            
            with open(output_path, 'w') as f:
                f.write(f"// Rule: {item['rule'].title}\n")
                f.write(f"// Source: {item['path']}\n")
                f.write(f"// MITRE: {', '.join(str(t) for t in item['rule'].tags)}\n")
                f.write(f"// Level: {item['rule'].level}\n\n")
                f.write(kql_query)
            
            print(f"  [KQL] {rule_name} → OK")
            success += 1
        except Exception as e:
            print(f"  [KQL] {Path(item['path']).stem} → FAILED: {e}")
            failed += 1
    
    print(f"\nSentinel conversion: {success} success, {failed} failed")
    return success, failed


def convert_to_crowdstrike(rules: list, output_dir: str):
    """Convert all rules to CrowdStrike LogScale CQL."""
    if not HAS_CROWDSTRIKE:
        print("Skipping CrowdStrike conversion (backend not installed)")
        return 0, 0
    
    os.makedirs(output_dir, exist_ok=True)
    backend = LogScaleBackend()
    
    success = 0
    failed = 0
    for item in rules:
        try:
            result = backend.convert_rule(item['rule'])
            cql_query = '\n'.join(result)
            
            rule_name = Path(item['path']).stem
            output_path = os.path.join(output_dir, f"{rule_name}.cql")
            
            with open(output_path, 'w') as f:
                f.write(f"// Rule: {item['rule'].title}\n")
                f.write(f"// Source: {item['path']}\n")
                f.write(f"// MITRE: {', '.join(str(t) for t in item['rule'].tags)}\n")
                f.write(f"// Level: {item['rule'].level}\n\n")
                f.write(cql_query)
            
            print(f"  [CQL] {rule_name} → OK")
            success += 1
        except Exception as e:
            print(f"  [CQL] {Path(item['path']).stem} → FAILED: {e}")
            failed += 1
    
    print(f"\nCrowdStrike conversion: {success} success, {failed} failed")
    return success, failed


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(project_root, 'rules')
    outputs_dir = os.path.join(project_root, 'outputs')
    
    print("=" * 60)
    print("DETECTION-AS-CODE: SIGMA RULE CONVERTER")
    print("=" * 60)
    
    # Load rules
    print(f"\n[1/4] Loading Sigma rules from {rules_dir}...")
    rules = load_sigma_rules(rules_dir)
    print(f"\nLoaded {len(rules)} rules total\n")
    
    if not rules:
        print("No rules found! Check your rules/ directory.")
        sys.exit(1)
    
    # Convert to each SIEM
    print("[2/4] Converting to Splunk SPL...")
    splunk_ok, splunk_fail = convert_to_splunk(
        rules, os.path.join(outputs_dir, 'splunk')
    )
    
    print("\n[3/4] Converting to Sentinel KQL...")
    sentinel_ok, sentinel_fail = convert_to_sentinel(
        rules, os.path.join(outputs_dir, 'sentinel')
    )
    
    print("\n[4/4] Converting to CrowdStrike CQL...")
    cs_ok, cs_fail = convert_to_crowdstrike(
        rules, os.path.join(outputs_dir, 'crowdstrike')
    )
    
    # Summary
    print("\n" + "=" * 60)
    print("CONVERSION SUMMARY")
    print("=" * 60)
    print(f"Rules loaded:       {len(rules)}")
    print(f"Splunk SPL:         {splunk_ok} OK / {splunk_fail} failed")
    print(f"Sentinel KQL:       {sentinel_ok} OK / {sentinel_fail} failed")
    print(f"CrowdStrike CQL:    {cs_ok} OK / {cs_fail} failed")
    print("=" * 60)
    
    # Exit with error if any conversions failed
    total_failures = splunk_fail + sentinel_fail + cs_fail
    if total_failures > 0:
        print(f"\n[WARN] {total_failures} total conversion failures!")
        sys.exit(1)
    else:
        print("\n[SUCCESS] All conversions passed!")


if __name__ == '__main__':
    main()
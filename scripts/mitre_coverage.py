#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Analyzer
Reads all Sigma rules and generates an ATT&CK Navigator layer
showing which techniques have detection coverage.
"""

import os
import glob
import json
import yaml
import re
from collections import defaultdict


def extract_mitre_tags(rules_dir: str) -> dict:
    """Extract MITRE technique IDs from all Sigma rules."""
    technique_map = defaultdict(list)  # technique_id -> [rule_titles]
    
    for yml_path in glob.glob(f"{rules_dir}/**/*.yml", recursive=True):
        try:
            with open(yml_path, 'r') as f:
                rule = yaml.safe_load(f)
            
            title = rule.get('title', 'Unknown')
            level = rule.get('level', 'unknown')
            tags = rule.get('tags', [])
            
            for tag in tags:
                # Match MITRE technique IDs like attack.t1059.001 or attack.t1059
                match = re.match(r'attack\.t(\d{4})(?:\.(\d{3}))?', tag.lower())
                if match:
                    tech_id = f"T{match.group(1)}"
                    if match.group(2):
                        tech_id += f".{match.group(2)}"
                    technique_map[tech_id].append({
                        'title': title,
                        'level': level,
                        'file': os.path.basename(yml_path)
                    })
        except Exception as e:
            print(f"[WARN] Could not parse {yml_path}: {e}")
    
    return technique_map


def generate_navigator_layer(technique_map: dict, output_path: str):
    """Generate ATT&CK Navigator JSON layer."""
    
    # Color by number of rules covering the technique
    def get_color(count):
        if count >= 3:
            return "#31a354"  # Dark green (well covered)
        elif count == 2:
            return "#74c476"  # Medium green
        elif count == 1:
            return "#a1d99b"  # Light green (minimal coverage)
        return ""  # No coverage = default (white)
    
    techniques = []
    for tech_id, rules in technique_map.items():
        techniques.append({
            "techniqueID": tech_id,
            "tactic": "",  # Navigator auto-maps to correct tactic
            "color": get_color(len(rules)),
            "comment": f"{len(rules)} rule(s): {', '.join(r['title'] for r in rules)}",
            "enabled": True,
            "score": len(rules)
        })
    
    layer = {
        "name": "Detection Coverage - Sigma Rules",
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Auto-generated from {sum(len(v) for v in technique_map.values())} Sigma rules covering {len(technique_map)} unique techniques",
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"]
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#a1d99b", "#31a354"],
            "minValue": 0,
            "maxValue": 3
        },
        "legendItems": [
            {"label": "No coverage", "color": "#ffffff"},
            {"label": "1 rule", "color": "#a1d99b"},
            {"label": "2 rules", "color": "#74c476"},
            {"label": "3+ rules", "color": "#31a354"}
        ]
    }
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(layer, f, indent=2)
    
    return layer


def print_coverage_report(technique_map: dict):
    """Print a human-readable coverage report."""
    print("\n" + "=" * 60)
    print("MITRE ATT&CK DETECTION COVERAGE REPORT")
    print("=" * 60)
    
    # Group by tactic (from tag names)
    print(f"\nTotal unique techniques covered: {len(technique_map)}")
    print(f"Total detection rules: {sum(len(v) for v in technique_map.values())}")
    
    print("\n--- Techniques with Coverage ---")
    for tech_id in sorted(technique_map.keys()):
        rules = technique_map[tech_id]
        levels = [r['level'] for r in rules]
        print(f"  {tech_id}: {len(rules)} rule(s) [{', '.join(levels)}]")
        for r in rules:
            print(f"    └── {r['title']} ({r['file']})")
    
    # Known high-priority techniques that SHOULD have coverage
    priority_techniques = [
        "T1059.001",  # PowerShell
        "T1059.003",  # Windows Command Shell
        "T1003.001",  # LSASS Memory
        "T1547.001",  # Registry Run Keys
        "T1053.005",  # Scheduled Task
        "T1105",      # Ingress Tool Transfer
        "T1071.001",  # Application Layer Protocol: Web
        "T1071.004",  # Application Layer Protocol: DNS
        "T1027",      # Obfuscated Files
        "T1059.004",  # Unix Shell
        "T1053.003",  # Cron
        "T1218",      # System Binary Proxy Execution
    ]
    
    missing = [t for t in priority_techniques if t not in technique_map]
    if missing:
        print(f"\n--- HIGH PRIORITY GAPS (techniques you should cover) ---")
        for tech_id in missing:
            print(f"  [GAP] {tech_id} — no detection rule!")
    else:
        print(f"\n[OK] All {len(priority_techniques)} high-priority techniques have coverage!")
    
    print("=" * 60)


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(project_root, 'rules')
    coverage_path = os.path.join(project_root, 'coverage', 'mitre-navigator.json')
    
    print("Loading Sigma rules and extracting MITRE tags...")
    technique_map = extract_mitre_tags(rules_dir)
    
    print(f"Generating ATT&CK Navigator layer → {coverage_path}")
    generate_navigator_layer(technique_map, coverage_path)
    
    print_coverage_report(technique_map)
    
    print(f"\n[INFO] Upload {coverage_path} to https://mitre-attack.github.io/attack-navigator/ to visualize")


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""
Golden Log Tester
Tests Sigma rules against known attack log samples to verify
true positive detection before deploying to production SIEMs.
"""

import os
import glob
import json
import yaml
import re
import sys


def load_golden_logs(logs_dir: str) -> list:
    """Load all golden log JSON files."""
    logs = []
    for json_path in glob.glob(f"{logs_dir}/**/*.json", recursive=True):
        try:
            with open(json_path, 'r') as f:
                log_data = json.load(f)
            logs.append({
                'path': json_path,
                'name': os.path.basename(json_path),
                'data': log_data
            })
        except Exception as e:
            print(f"[WARN] Failed to load {json_path}: {e}")
    return logs


def check_field_match(log_data: dict, field: str, values: list, modifier: str = 'contains') -> bool:
    """Check if a log field matches the detection criteria."""
    # Handle field name with modifier (e.g., Image|endswith)
    field_name = field.split('|')[0]
    
    # Get the field value from the log
    log_value = log_data.get(field_name, '')
    if not log_value:
        return False
    
    log_value_lower = str(log_value).lower()
    
    for pattern in values:
        pattern_lower = str(pattern).lower().strip('\\')
        
        if 'endswith' in modifier:
            if log_value_lower.endswith(pattern_lower):
                return True
        elif 'startswith' in modifier:
            if log_value_lower.startswith(pattern_lower):
                return True
        elif 'contains' in modifier:
            if pattern_lower in log_value_lower:
                return True
        elif 're' in modifier:
            if re.search(pattern, str(log_value), re.IGNORECASE):
                return True
        else:
            if log_value_lower == pattern_lower:
                return True
    
    return False


def test_rule_against_log(rule_path: str, log_data: dict) -> bool:
    """Simple test: does the rule's detection logic match the log event?"""
    with open(rule_path, 'r') as f:
        rule = yaml.safe_load(f)
    
    detection = rule.get('detection', {})
    condition = detection.get('condition', '')
    
    # Evaluate each selection
    selection_results = {}
    for key, criteria in detection.items():
        if key == 'condition':
            continue
        if not isinstance(criteria, dict):
            continue
        
        # Check all fields in this selection
        all_match = True
        for field, values in criteria.items():
            if not isinstance(values, list):
                values = [values]
            
            modifier = field if '|' in field else 'contains'
            if not check_field_match(log_data, field, values, modifier):
                all_match = False
                break
        
        selection_results[key] = all_match
    
    # Simple condition evaluation
    # This handles basic "selection" and "sel1 and sel2" patterns
    # A full implementation would parse the condition properly
    if 'selection' in selection_results and condition == 'selection':
        return selection_results['selection']
    
    # For "selection_x and selection_y" patterns
    if ' and ' in condition and ' or ' not in condition:
        parts = [p.strip() for p in condition.replace('(', '').replace(')', '').split(' and ')]
        parts = [p for p in parts if not p.startswith('not ')]
        return all(selection_results.get(p, False) for p in parts if p in selection_results)
    
    # For "selection_x or selection_y" patterns
    if ' or ' in condition:
        parts = [p.strip() for p in condition.replace('(', '').replace(')', '').split(' or ')]
        return any(selection_results.get(p, False) for p in parts if p in selection_results)
    
    # Default: check if the named selection matches
    return selection_results.get(condition, False)


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(project_root, 'rules')
    logs_dir = os.path.join(project_root, 'tests', 'golden-logs')
    
    print("=" * 60)
    print("GOLDEN LOG TEST SUITE")
    print("=" * 60)
    
    # Load golden logs
    golden_logs = load_golden_logs(logs_dir)
    print(f"\nLoaded {len(golden_logs)} golden log samples")
    
    # Load rules
    rule_files = glob.glob(f"{rules_dir}/**/*.yml", recursive=True)
    print(f"Found {len(rule_files)} Sigma rules\n")
    
    # Test each rule against each log
    results = []
    for rule_path in rule_files:
        rule_name = os.path.basename(rule_path)
        for log in golden_logs:
            try:
                matched = test_rule_against_log(rule_path, log['data'])
                status = "✅ MATCH" if matched else "— no match"
                results.append({
                    'rule': rule_name,
                    'log': log['name'],
                    'matched': matched
                })
                if matched:
                    print(f"  {status}: {rule_name} ← {log['name']}")
            except Exception as e:
                print(f"  ❌ ERROR: {rule_name} ← {log['name']}: {e}")
    
    # Summary
    matches = sum(1 for r in results if r['matched'])
    total = len(results)
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {matches} matches out of {total} tests")
    print(f"{'=' * 60}")
    
    if matches == 0:
        print("\n[WARN] No golden log matches found. This could mean:")
        print("  1. Rules and golden logs don't align (field names differ)")
        print("  2. Golden logs need updating")
        print("  3. Test script condition parser needs enhancement")


if __name__ == '__main__':
    main()
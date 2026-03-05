import os
import csv
import re
import json

def clean_json_string(s):
    # Remove newlines and extra spaces
    s = ' '.join(s.split())
    return s

def extract_risk_params(file_path):
    risk_params = []
    current_rule = None
    
    with open(file_path, 'r') as f:
        content = f.readlines()
    
    for i, line in enumerate(content):
        # Find rule name
        if line.startswith('['):
            current_rule = line.strip('[]\\n').strip()
            continue
            
        # Look for risk parameters
        if '_risk = [' in line or '_risk=[' in line:
            try:
                # Start collecting the JSON string
                json_str = line.split('=', 1)[1].strip()
                j = i + 1
                # Keep reading lines until we find a complete JSON array
                while j < len(content) and not json_str.rstrip().endswith(']'):
                    json_str += ' ' + content[j].strip()
                    j += 1
                
                # Clean the JSON string
                json_str = clean_json_string(json_str)
                print(f"\nProcessing rule: {current_rule}")
                print(f"Found risk JSON: {json_str}")
                
                # Extract rule name without the "Rule" suffix and clean it
                clean_rule_name = current_rule.replace(' - Rule', '')
                # Remove leading word before hyphen and trailing ]
                clean_rule_name = re.sub(r'^[^-]*-\s*', '', clean_rule_name)
                clean_rule_name = clean_rule_name.rstrip(']')
                
                # Parse JSON and extract risk_object_type and risk_score values
                try:
                    risk_objects = json.loads(json_str)
                    for obj in risk_objects:
                        # Try both risk_object_type and threat_object_type
                        risk_type = obj.get('risk_object_type') or obj.get('threat_object_type', '')
                        risk_score = obj.get('risk_score', '')
                        if risk_type:
                            risk_params.append({
                                'rule_name': clean_rule_name,
                                'risk_object_type': risk_type,
                                'risk_score': risk_score
                            })
                except json.JSONDecodeError:
                    print(f"Error parsing JSON for rule: {clean_rule_name}")
                    continue
                
            except Exception as e:
                print(f"Error processing rule: {current_rule}")
                print(f"Error: {str(e)}")
                continue
    
    return risk_params

def main():
    # Directory containing savedsearches.conf files
    conf_dir = 'packages'
    
    all_risk_params = []
    
    # Walk through all packages directories
    for root, dirs, files in os.walk(conf_dir):
        if 'savedsearches.conf' in files:
            file_path = os.path.join(root, 'savedsearches.conf')
            print(f"\nProcessing file: {file_path}")
            risk_params = extract_risk_params(file_path)
            all_risk_params.extend(risk_params)
    
    # Write to CSV
    if all_risk_params:
        fieldnames = ['rule_name', 'risk_object_type', 'risk_score']
        
        with open('risk_parameters.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for param in all_risk_params:
                writer.writerow(param)
        
        print(f"\nSuccessfully wrote {len(all_risk_params)} risk parameters to risk_parameters.csv")
    else:
        print("\nNo risk parameters found")

if __name__ == "__main__":
    main() 
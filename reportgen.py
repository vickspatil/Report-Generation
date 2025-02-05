import pandas as pd
import os
import cohere
from pathlib import Path
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv

def process_files(directory_path, cohere_api_key):
    """Process all CSV and Excel files (including all sheets) in the directory and extract insights."""
    co = cohere.Client(cohere_api_key)
    all_data = []
    
    for file in Path(directory_path).glob('*'):
        try:
            if file.suffix.lower() == '.csv':
                df = pd.read_csv(file)
                all_data.append(df)
            elif file.suffix.lower() in ['.xls', '.xlsx']:
                excel_file = pd.ExcelFile(file)
                for sheet_name in excel_file.sheet_names:
                    df = excel_file.parse(sheet_name)
                    all_data.append(df)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    # Merge all data into one dataframe
    combined_df = pd.concat(all_data, ignore_index=True, sort=False)
    
    # Key insights extraction
    total_rows = len(combined_df)
    severity_counts = combined_df['Severity'].value_counts().to_dict() if 'Severity' in combined_df else {}
    
    top_vulnerabilities = Counter(combined_df['Problem Name'].dropna()).most_common(5) if 'Problem Name' in combined_df else []
    
    impacted_os = Counter(combined_df['OS Name'].dropna()).most_common(5) if 'OS Name' in combined_df else []
    
    affected_software = Counter(combined_df['Software Name'].dropna()).most_common(5) if 'Software Name' in combined_df else []
    
    cve_counts = Counter(combined_df['CVE'].dropna()).most_common(5) if 'CVE' in combined_df else []
    
    summary_info = f"""Total vulnerabilities recorded: {total_rows}\n
Severity Breakdown: {severity_counts}\n
Top 5 Most Frequent Vulnerabilities:\n{top_vulnerabilities}\n
Top 5 Most Impacted Operating Systems:\n{impacted_os}\n
Top 5 Most Affected Software:\n{affected_software}\n
Most Repeated CVEs:\n{cve_counts}\n"""
    
    # Get AI-generated insights
    prompt = f"""As a cybersecurity analyst, analyze the following data summary:\n\n{summary_info}\n\nIdentify:\n1. Key risks and concerns\n2. Patterns in vulnerability distribution\n3. Any major security trends\n4. Recommendations to mitigate the risks\n"""
    
    response = co.generate(
        prompt=prompt,
        max_tokens=400,
        temperature=0.3,
        presence_penalty=0.5
    )
    
    return {
        'key_statistics': summary_info,
        'ai_analysis': response.generations[0].text,
        'timestamp': datetime.now()
    }

def generate_markdown_report(analysis):
    """Generate markdown report with analytical insights."""
    report = f"""# Cybersecurity Vulnerability Report\nGenerated on: {analysis['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n\n## Key Statistics\n```
{analysis['key_statistics']}\n```\n\n## AI-Generated Insights\n{analysis['ai_analysis']}\n"""
    return report

def main(directory_path, cohere_api_key):
    results = process_files(directory_path, cohere_api_key)
    report = generate_markdown_report(results)
    output_file = f"cybersecurity_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(output_file, 'w') as f:
        f.write(report)
    return output_file
load_dotenv()
cohere_api_key = os.getnv("COHERE_API_KEY")
directory_path = os.getenv("DATA_DIRECTORY")
output_file = main(directory_path, cohere_api_key)

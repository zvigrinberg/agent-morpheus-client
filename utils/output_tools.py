def generate_markdown(output) -> tuple[str, str, str, bool]:
    results = []
    for evaluation in output:
        vuln_id = evaluation['vuln_id']
        summary = evaluation['summary']
        checklist = evaluation['checklist']
        justification = evaluation['justification']
        justification_label = justification['label']
        justification_reason = justification['reason']
        justification_status = justification['status']
        status_badge = ''
        if justification_status == 'FALSE':
            status_badge = f"![{justification_label}](https://img.shields.io/badge/{justification_label}-green)"
        else:
            status_badge = f"![{justification_label}](https://img.shields.io/badge/{justification_label}-red)"
        checklist_md = ''
        for item in checklist:
            question = item['input']
            response = item['response']
            checklist_md += f"""
**Q: {question}**

**A:** {response}

"""
        results.append([vuln_id, f"""
## {vuln_id}

### Checklist

{checklist_md}

### Summary

{summary}

### Justification

{status_badge}

{justification_reason}
"""])
    return results

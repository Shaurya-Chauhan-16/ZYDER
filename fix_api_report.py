with open("api.py", "r") as f:
    content = f.read()

old_report_return = """        return response
    except HTTPException:"""

new_report_return = """        return sanitize_for_json(response)
    except HTTPException:"""

content = content.replace(old_report_return, new_report_return)

with open("api.py", "w") as f:
    f.write(content)

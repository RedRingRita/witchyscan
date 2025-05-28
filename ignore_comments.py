# ignore_comments.py

def init_comment_state():
    return {
        "in_multiline_comment": False,
        "multiline_comment_delim": None,
        "in_bash_comment_block": False,
    }

def should_ignore_line(line, language, state):
    stripped = line.strip()

    if language == "php":
        if '/*' in stripped:
            state["in_multiline_comment"] = True
        if '*/' in stripped:
            state["in_multiline_comment"] = False
            return True
        if state["in_multiline_comment"]:
            return True

    elif language == "python":
        if not state["in_multiline_comment"]:
            if stripped.startswith(('"""', "'''")):
                delim = stripped[:3]
                if stripped.count(delim) == 2:
                    return True
                state["in_multiline_comment"] = True
                state["multiline_comment_delim"] = delim
                return True
        else:
            if state["multiline_comment_delim"] in stripped:
                state["in_multiline_comment"] = False
                state["multiline_comment_delim"] = None
            return True

    elif language == "bash":
        if not state["in_bash_comment_block"]:
            if stripped.startswith(": '") or stripped.startswith(': "'):
                state["in_bash_comment_block"] = True
                return True
        else:
            if stripped.endswith("'") or stripped.endswith('"'):
                state["in_bash_comment_block"] = False
                return True
        if stripped.startswith("#") or stripped == "":
            return True

    if language in ["php", "python"]:
        if stripped.startswith("//") or stripped.startswith("#") or stripped == "":
            return True

    return False

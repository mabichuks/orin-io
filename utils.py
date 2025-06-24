import json

def get_json_from_path(path: str):
    with open(path, 'r', encoding='utf-8') as file:
        return json.load(file)

import requests

from utils.client_model import SUPPORTED_LANGUAGES

template = 'https://api.github.com/repos/{repo_name}/languages'


def get_languages(repo_name: str) -> list[str]:
    response = requests.get(template.format(repo_name=repo_name))
    if response.ok:
        languages = response.json()
        known_languages = []
        for language in languages.keys():
            if language in SUPPORTED_LANGUAGES:
                known_languages.append(language)
        return known_languages
    raise Exception(f'GitHub - get_languages: {response.status_code} - {response.reason}')

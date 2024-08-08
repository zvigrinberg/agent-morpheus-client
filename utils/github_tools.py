import requests

template = 'https://api.github.com/repos/{repo_name}/languages'

def get_main_language(repo_name: str) -> str:
  response = requests.get(template.format(repo_name=repo_name))
  if response.ok:
    languages = response.json()
    top: dict = []
    for language in languages.keys():
      if top == [] or languages[language] > top[1]:
        top = (language, languages[language])
      
    return top[0]
  raise Exception(f'GitHub - get_main_language: {response.status_code} - {response.reason}')
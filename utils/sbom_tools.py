from pydantic import BaseModel
from utils.github_tools import get_main_language

class GitRepoRef(BaseModel):
  ref: str
  commit_id: str
  language: str

class SbomInput(BaseModel):
  name: str
  tag: str
  repo_ref: GitRepoRef
  sbom: dict

def __get_property(props, name) -> str | None:
  for prop in props:
    if prop['name'] == name:
      return prop['value']
  return None

def parse_sbom(sbom) -> SbomInput:
  name = sbom['metadata']['component']['name']
  tag = sbom['metadata']['component']['version']
  props = sbom['metadata']['properties']
  repo_ref = __get_property(props, 'syft:image:labels:io.openshift.build.source-location')
  commit_url = __get_property(props, 'syft:image:labels:io.openshift.build.commit.url')
  commit_id = commit_url.split('/')[-1]
  language=get_main_language(repo_ref.removeprefix('https://github.com/'))
  return SbomInput(name=name, tag=tag, sbom=sbom, repo_ref=GitRepoRef(ref=repo_ref, commit_id=commit_id, language=language))
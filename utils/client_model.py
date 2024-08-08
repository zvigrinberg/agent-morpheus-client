from typing import Any
from pydantic import BaseModel, Field

from utils.sbom_tools import SbomInput

class SourceInfo(BaseModel):
  type: str
  git_repo: str
  commit_id: str
  include: list[str]
  exclude: list[str] | None = None

class SbomInfo(BaseModel):
  type: str = Field(serialization_alias='_type')
  format: str
  content: dict

class Image(BaseModel):
  name: str
  tag: str
  source_info: list[SourceInfo]
  sbom_info: SbomInfo

class Vuln(BaseModel):
  vuln_id: str

class Scan(BaseModel):
  vulns: list[Vuln]

class InputRequest(BaseModel):
  image: Image
  scan: Scan

def __get_includes(language: str) -> list[str]:
  match language:
    case 'Go': return [
      "**/*.go",
      "go.*",
      "Dockerfile*"
    ]
    case 'Docs': return [
      "**/*.md",
      "docs/**/*.rst"
    ]
    case _: return []

def __get_excludes(language: str) -> list[str]:
  match language:
    case 'Go': return [
      "test/**/*",
      "vendor/**/*"
    ]
    case _: return []
    
def build_image_from_sbom(sbom: SbomInput) -> Image:
  sbom_info=SbomInfo(type='json', format='cyclonedx+json', content=sbom.sbom)
  sources = [SourceInfo(type='code', git_repo=sbom.repo_ref.ref, commit_id=sbom.repo_ref.commit_id, include=__get_includes(sbom.repo_ref.language), exclude=__get_excludes(sbom.repo_ref.language)),
             SourceInfo(type='doc', git_repo=sbom.repo_ref.ref, commit_id=sbom.repo_ref.commit_id, include=__get_includes('Docs'), exclude=__get_excludes('Docs'))]
  return Image(name=sbom.name, tag=sbom.tag, source_info=sources, sbom_info=sbom_info)
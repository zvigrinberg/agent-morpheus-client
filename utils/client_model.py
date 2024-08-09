from typing import Any
from pydantic import BaseModel, Field

SUPPORTED_LANGUAGES = ['Go', 'Python', 'Dockerfile', 'Java', 'TypeScript', 'JavaScript']

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

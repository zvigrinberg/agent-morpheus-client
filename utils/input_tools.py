import streamlit as st

from utils.client_model import SUPPORTED_LANGUAGES, Image, InputRequest, SbomInfo, Scan, SourceInfo, Vuln
from utils.sbom_tools import SbomInput
def __get_includes(language: str) -> list[str]:
  match language:
    case 'Go': return [
      "**/*.go",
      "go.*",
    ]
    case 'Python': return [
      "**/*.py",          # All Python source files
      "requirements.txt", # Pip dependencies
      "Pipfile",          # Pipenv dependencies
      "Pipfile.lock",     # Locked Pipenv dependencies
      "pyproject.toml",   # PEP 518/517 build system
      "setup.py",         # Setuptools configuration
      "setup.cfg",        # Alternate setuptools configuration
    ]
    case 'Java': return [
      "**/*.java",             # All Java source files
      "pom.xml",               # Maven build file
      "build.gradle",          # Gradle build script
      "settings.gradle",       # Gradle settings file
      "src/main/**/*",         # Main Java source files
    ]
    case 'JavaScript': return [
      "**/*.js",               # All JavaScript source files
      "**/*.jsx",              # JSX files for React
      "package.json",          # Node.js project file
      "package-lock.json",     # Locked versions of Node dependencies
      "yarn.lock",             # Yarn lockfile for dependencies
      "webpack.config.js",     # Webpack configuration
      "rollup.config.js",      # Rollup configuration
      "babel.config.js",       # Babel configuration
      ".babelrc",              # Alternate Babel configuration
      ".eslintrc.js",          # ESLint configuration
      ".eslintrc.json",        # Alternate ESLint configuration
      "tsconfig.json",         # TypeScript configuration
      "*.config.js",           # Other JS configuration files
      "*.config.json",         # JSON configuration files
      "public/**/*",           # Public assets (images, icons, etc.)
      "src/**/*",              # Main source files directory
    ]
    case 'TypeScript': return [
      "**/*.ts",               # All TypeScript source files
      "**/*.tsx",              # TSX files for React (TypeScript)
      "package.json",          # Node.js project file
      "package-lock.json",     # Locked versions of Node dependencies
      "yarn.lock",             # Yarn lockfile for dependencies
      "tsconfig.json",         # TypeScript configuration
      "tsconfig.*.json",       # TypeScript environment-specific configurations
      "webpack.config.js",     # Webpack configuration
      "webpack.config.ts",     # Webpack configuration in TypeScript
      "rollup.config.js",      # Rollup configuration
      "rollup.config.ts",      # Rollup configuration in TypeScript
      "babel.config.js",       # Babel configuration
      ".babelrc",              # Alternate Babel configuration
      ".eslintrc.js",          # ESLint configuration
      ".eslintrc.json",        # Alternate ESLint configuration
      "*.config.js",           # Other JS configuration files
      "*.config.ts",           # Other TS configuration files
      "*.json",                # JSON configuration files
      "src/**/*",              # Main source files directory
      "public/**/*",           # Public assets (images, icons, etc.)
      "assets/**/*",           # Additional assets directory
    ]
    case 'Dockerfile': return [
      "Dockerfile*",            # Main Dockerfile
      "docker-compose.yml",    # Docker Compose configuration
      "*.dockerfile",          # Additional Dockerfiles with different names
      "*.dockerignore",        # Docker ignore files
      "docker-compose.*.yml",  # Environment-specific Docker Compose files
      "*.sh",                  # Shell scripts used in the Docker build process
      "scripts/**/*",          # Any custom scripts used in the Docker setup
      "*.env",                 # Environment variable files
      "*.yaml",                # YAML configuration files
      "*.yml",                 # YAML configuration files
      "*.json",                # JSON configuration files
      "config/**/*",           # Configuration files relevant to Docker
      "conf.d/**/*",           # Additional configuration directories
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
    case 'Java': return [
      "target/**/*",           # Maven build output directory
      "build/**/*",            # Gradle build output directory
      "*.class",               # Compiled Java classes
      ".gradle/**/*",          # Gradle cache
      ".mvn/**/*",             # Maven wrapper files
      ".gitignore",            # Git ignore file
      "test/**/*",             # Test source files
      "tests/**/*",            # Alternate test directories
      "src/test/**/*",         # Test files in the test source set
    ]
    case 'JavaScript': return [
      "node_modules/**/*",     # Node.js dependencies
      "dist/**/*",             # Distribution files
      "build/**/*",            # Build output directories
      "test/**/*",             # Test source files
      "tests/**/*",            # Alternate test directories
      "example/**/*",          # Example files or directories
      "examples/**/*",         # Alternate example directories
    ]
    case 'TypeScript': return [
      "node_modules/**/*",     # Node.js dependencies
      "dist/**/*",             # Distribution files
      "build/**/*",            # Build output directories
      "test/**/*",             # Test source files
      "tests/**/*",            # Alternate test directories
      "example/**/*",          # Example files or directories
      "examples/**/*",         # Alternate example directories
    ]
    case 'Python': return [
      "tests/**/*",          # Test files and directories
      "test/**/*",           # Alternate naming for test directories
      "venv/**/*",           # Virtual environment files
      ".venv/**/*",          # Alternate virtual environment directory
      "env/**/*",            # Another common virtual environment directory
      "build/**/*",          # Build directories
      "dist/**/*",           # Distribution directories
      ".mypy_cache/**/*",    # Mypy cache
      ".pytest_cache/**/*",  # Pytest cache
      "__pycache__/**/*",    # Python bytecode
      "*.pyc",               # Python compiled bytecode files
      "*.pyo",               # Optimized bytecode files
      "*.pyd",               # Windows compiled files
      ".github/**/*",        # GitHub workflows and configurations
    ]
    case _: return []

def __build_includes(languages: list[str]) -> list[str]:
  includes = []
  for language in languages:
    includes += __get_includes(language)
  return includes

def __build_excludes(languages: list[str]) -> list[str]:
  excludes = []
  for language in languages:
    excludes += __get_excludes(language)
  return excludes

def build_image_from_sbom(sbom: SbomInput) -> Image:
  sbom_info=SbomInfo(type='json', format='cyclonedx+json', content=sbom.sbom)
  sources = [SourceInfo(type='code', git_repo=sbom.repo_ref.ref, commit_id=sbom.repo_ref.commit_id, include=__build_includes(sbom.repo_ref.languages), exclude=__build_excludes(sbom.repo_ref.languages)),
             SourceInfo(type='doc', git_repo=sbom.repo_ref.ref, commit_id=sbom.repo_ref.commit_id, include=__get_includes('Docs'), exclude=__get_excludes('Docs'))]
  return Image(name=sbom.name, tag=sbom.tag, source_info=sources, sbom_info=sbom_info)

def build_input() -> InputRequest:
  sbom: SbomInput = st.session_state.sbom
  cves_text = st.session_state.cves
  st.session_state['morpheus_waiting'] = True
  
  cves = [cve.strip() for cve in cves_text.split(',')]
  scan=Scan(vulns=[Vuln(vuln_id=cve) for cve in cves])
  input_data = InputRequest(image=build_image_from_sbom(sbom), scan=scan)
  return input_data

def print_input_data(col):
  col.header('Input Data')
  if 'sbom' in st.session_state:
    sbom: SbomInput = st.session_state.sbom

    col.markdown(f"""
- Name: {sbom.name}
- Tag: {sbom.tag}
- Source Ref: [{sbom.repo_ref.ref}@{sbom.repo_ref.commit_id}]({sbom.repo_ref.ref}/tree/{sbom.repo_ref.commit_id})
""")
    st.session_state.sbom.repo_ref.languages = col.multiselect("Select the programming languages to use in the includes/excludes:", SUPPORTED_LANGUAGES, sbom.repo_ref.languages)
  else:
    col.text('Load an SBOM to show the input data')
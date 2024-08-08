import requests
import streamlit as st
import os
import json
from pathlib import Path

from utils.client_model import InputRequest, Scan, Vuln, build_image_from_sbom
from utils.sbom_tools import SbomInput, parse_sbom
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from callback.http_callback import HttpCallback

st.set_page_config(page_title='Morpheus Client', layout='wide')

data_dir = os.getenv("DATA_DIR", '/data')
if not os.path.isdir(data_dir):
  raise ValueError('Missing required data dir: ' + data_dir)

if 'callback' not in st.session_state:
  st.session_state.callback = {}

def on_receive_callback(data):
  st.session_state['morpheus_waiting'] = False
  with open(Path(data_dir, 'output.json'), 'w') as f:
    json.dump(data, f)

callback_server = HttpCallback()

if not hasattr(st, 'callback_server_listening'):
  st.callback_server_listening = True
  if __name__ == '__main__':
    callback_server.serve(on_receive=on_receive_callback)

MORPHEUS_URL=os.getenv("MORPHEUS_URL")
if MORPHEUS_URL is None:
  raise ValueError('Missing required enviroment variable MORPHEUS_URL')

st.title("Agent Morpheus client")

def set_data_ready():
  st.session_state['data_ready'] = 'sbom' in st.session_state and 'cves' in st.session_state

def is_running():
  git_loading = False
  morpheus_waiting = False
  if 'git_loading' in st.session_state:
    git_loading = st.session_state['git_loading']
  if 'morpheus_waiting' in st.session_state:
    morpheus_waiting = st.session_state['morpheus_waiting']
  return git_loading or morpheus_waiting

if 'running' not in st.session_state:
  st.session_state['running'] = False

st.session_state['running'] = is_running()

if 'data_ready' not in st.session_state:
  st.session_state['data_ready'] = False

def update_file():
  if 'input_file' in st.session_state:
    file = st.session_state.input_file
    if file is not None:
      st.session_state['git_loading'] = True
      data = json.loads(file.getvalue())
      try:
        sbom = parse_sbom(data)
        st.session_state.sbom = sbom
        st.session_state['git_loading'] = False
        set_data_ready()
      except Exception as exc:
        main_col.error(exc.message)
      

def build_input() -> InputRequest:
  sbom: SbomInput = st.session_state.sbom
  cves_text = st.session_state.cves
  st.session_state['morpheus_waiting'] = True
  
  cves = [cve.strip() for cve in cves_text.split(',')]
  scan=Scan(vulns=[Vuln(vuln_id=cve) for cve in cves])
  input_data = InputRequest(image=build_image_from_sbom(sbom), scan=scan)
  return input_data

def send_to_morpheus():
  data = build_input()

  response = requests.post(MORPHEUS_URL, data=data.model_dump_json(by_alias=True).encode('utf-8'))
  if not response.ok:
    st.session_state['running'] = False
    main_col.error(f'Morpheus backend error: {response.status_code} - {response.reason}')

def save_file():
  with open(Path(data_dir, 'input.json'), 'w') as f:
    data = build_input()
    f.write(data.model_dump_json(by_alias=True, indent=True))
    f.close()
  st.session_state['morpheus_waiting'] = False

main_col, helper_col = st.columns([2, 5])
main_col.header("Build Morpheus Request")

st.session_state.cves=main_col.text_input(label='CVEs', placeholder='CVE-2024-27304, CVE-2024-2961, ...', value='CVE-2024-27304', on_change=set_data_ready)
st.session_state.input_file=main_col.file_uploader("Pick a CycloneDX SBOM File generated form Syft")
update_file()
main_col.button('Send to Morpheus', on_click=send_to_morpheus, type='primary', disabled=is_running() or not st.session_state['data_ready'])
main_col.button('Save Morpheus Input', on_click=save_file, type='secondary', disabled=not st.session_state['data_ready'])

helper_col.header('Input Data')
if 'sbom' in st.session_state:
  input_data = build_input()
  helper_col.text('Name: ' + input_data.image.name )
  helper_col.text('Tag: ' + input_data.image.tag)
  helper_col.text('Source: ' + input_data.image.source_info[0].git_repo)
  helper_col.text('Commit Id: ' + input_data.image.source_info[0].commit_id)
else:
  helper_col.text('Load an SBOM to show the input data')

def print_output():
 callback_file = Path(data_dir, 'output.json')
 if callback_file.is_file():
  with open(callback_file, 'r') as f:
    st.header('Callback')
    st.write(json.load(f))

print_output()

class OutputEventHandler(FileSystemEventHandler):

  def __init__(self, hook):
    self.hook = hook

  def on_modified(self, event):
    self.hook()

def monitor_output():
  observer = Observer()
  observer.schedule(OutputEventHandler(print_output),'output.json', recursive=False)
  observer.start()

monitor_output()
# Morpheus Client

This client application aims to simplify the interaction with Agent Morpheus and the visualization of the resulting reports.
The Agent Morpheus service has to be configured to send an HTTP post with the report to this service at 
`http://agent-morpheus-client:8081/results`

It allows you to generate the input file and to send it directly or download it if needed.

The input has to be a CycloneDX SBOM and a comma-separated list of CVEs. From the SBOM, the application will extract the
repository, commit_id and container image:tag to use in the input file.

Besides, from the repository, using the GitHub api will query the languages. These languages will be used to generate
the includes and excludes.

## Run locally

```bash
MORPHEUS_URL=http://agent-morpheus/scan
DATA_DIR=./data
streamlit run morpheus_client.py
```

## Run the container image

```bash
podman run --name=morpheus-client --rm -v ./data:/data:z -p 8080:8080 -e MORPHEUS_URL=http://agent-morpheus/scan quay.io/ruben/morpheus-client:latest
```

## Run on OpenShift

The existing yaml file will create a deployment and a service that exposes ports 8080 (for the UI) and 8081 (for the callback service)

```bash
oc apply -f deploy/agent_morpheus_client.yaml
```

If you need the output files to be persisted you can use a PersistenceVolumeClaim instead of `emptyDir`
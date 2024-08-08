FROM registry.access.redhat.com/ubi8/python-311

COPY . /app

ENV CALLBACK_DIR=/data
ENV CALLBACK_PORT=8081

EXPOSE 8080
EXPOSE 8081

WORKDIR /app

RUN pip3 install -r requirements.txt

ENTRYPOINT ["streamlit", "run", "morpheus_client.py", "--server.port=8080", "--server.address=0.0.0.0"]
FROM python@sha256:63f6d26c66126481336273c8d34a2017729843ac3b2de2897c428f27e066f1be AS app

WORKDIR /usr/src/app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py main.py

ENTRYPOINT ["python", "./main.py"]


FROM app as enclaved-app
RUN apk add --no-cache socat iproute2
RUN pip install --no-cache-dir supervisor

COPY enclave/supervisord.conf /etc/supervisor/supervisord.conf
COPY enclave/log_forwarder.py /opt/log_forwarder.py
COPY enclave/run.sh /opt/run.sh
RUN chmod +x /opt/run.sh

ENTRYPOINT ["/opt/run.sh"]


FROM app AS final

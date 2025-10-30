FROM python@sha256:63f6d26c66126481336273c8d34a2017729843ac3b2de2897c428f27e066f1be AS app-base

WORKDIR /usr/src/app

RUN apk add --no-cache socat iproute2

ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py main.py

COPY enclave/supervisord.conf /etc/supervisor/supervisord.conf
COPY enclave/supervisor_logging.py /opt/supervisor_logging.py
COPY enclave/run.sh /opt/run.sh

RUN chmod +x /opt/run.sh

ENTRYPOINT ["/opt/run.sh"]

FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN yum install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel socat -y

COPY output/app.eif /root
COPY run.sh /opt
COPY prestop-hook.sh /opt
RUN chmod +x /opt/run.sh
RUN chmod +x /opt/prestop-hook.sh

ENTRYPOINT [ "/opt/run.sh" ]

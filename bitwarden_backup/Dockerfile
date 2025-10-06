FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /bitwarden_workdir

RUN apt update && apt install -y curl unzip libsecret-1-0 jq python3 python3-pip python3-venv cron

COPY src/ /bitwarden_workdir
COPY requirements.txt /bitwarden_workdir/requirements.txt

RUN apt update && apt install -y curl jq python3 python3-pip python3-venv
RUN python3 -m venv /bitwarden_venv
ENV PATH="/bitwarden_venv/bin:$PATH"
RUN pip3 install --no-cache-dir -r /bitwarden_workdir/requirements.txt

ENTRYPOINT ["python3", "-m", "backup"]

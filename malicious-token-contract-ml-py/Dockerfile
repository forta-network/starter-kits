# Build stage: compile Python dependencies
FROM ubuntu:focal as builder
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:deadsnakes/ppa
RUN apt-get install -y python3.10 python3.10-distutils
RUN apt-get install -y python3-pip
RUN apt-get install -y build-essential libffi-dev python3.10-dev  # for building C extensions
RUN apt-get install -y wget
RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python3.10 get-pip.py
COPY requirements.txt ./
COPY forta_bot-0.2.0.tar.gz ./
RUN python3.10 -m pip install --user -r requirements.txt

# Final stage: copy over Python dependencies
FROM ubuntu:focal
RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository -y ppa:deadsnakes/ppa
RUN apt-get install -y python3.10
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local:$PATH
ENV FORTA_ENV=production
ENV PYTHONUNBUFFERED=1
LABEL "network.forta.settings.agent-logs.enable"="true"
WORKDIR /app
COPY malicious_non_token_model_02_07_23_exp6.joblib ./
COPY LICENSE.md ./
COPY ./src ./src
CMD ["python3.10", "./src/agent.py"]

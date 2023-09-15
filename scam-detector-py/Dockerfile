# Build stage: compile Python dependencies
FROM ubuntu:focal as builder
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y python3 pip
RUN python3 -m pip install --upgrade pip
COPY requirements.txt ./
RUN python3 -m pip install --user -r requirements.txt --no-cache-dir
# Installing PyTorch out of the requirements to avoid the CUDA dependency
RUN python3 -m pip install --user torch --index-url https://download.pytorch.org/whl/cpu --no-cache-dir
# Final stage: copy over Python dependencies and install production Node dependencies
FROM ubuntu:focal
# this python version should match the build stage python version
RUN apt-get update
RUN apt-get -y install curl gnupg
RUN curl -sL https://deb.nodesource.com/setup_14.x  | bash -
RUN apt-get -y install nodejs
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local:$PATH
ENV NODE_ENV=production
# Uncomment the following line to enable agent logging
LABEL "network.forta.settings.agent-logs.enable"="true"
WORKDIR /app
COPY ./fp_list.csv ./
COPY ./quality_metrics.json ./
COPY ./v3_scammer_model.joblib ./
COPY ./manual_alert_list.tsv ./
COPY ./LICENSE ./
COPY ./basebot_parsing_config.csv ./
COPY ./src ./src
COPY package*.json ./
RUN npm ci --production
CMD [ "npm", "run", "start:prod" ]
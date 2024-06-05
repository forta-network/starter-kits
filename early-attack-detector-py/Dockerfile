# Build stage: compile Python dependencies
FROM python:3.11-slim-bullseye as builder
RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y python3 pip
# Required for lightgbm
# RUN apt-get install libgomp1  
RUN python3 -m pip install --upgrade pip
COPY requirements.txt ./
RUN python3 -m pip install --user -r requirements.txt --no-cache-dir

# Final stage: copy over Python dependencies and install production Node dependencies
FROM python:3.11-slim-bullseye
# this python version should match the build stage python version
RUN apt-get update
RUN apt-get -y install curl gnupg
RUN apt-get install nodejs -y
RUN node --version
RUN apt-get install npm -y
RUN npm --version
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local:$PATH
ENV NODE_ENV=production
# Uncomment the following line to enable agent logging
LABEL "network.forta.settings.agent-logs.enable"="true"
WORKDIR /app
COPY ./src ./src
COPY ./tp_list.csv ./
COPY ./deployed_models ./deployed_models
COPY package*.json ./
COPY requirements.txt ./
COPY requirements_dev.txt ./
# This is needed for web3 compatibility with python 3.11. See https://stackoverflow.com/questions/74711405/importerror-cannot-import-name-getargspec-from-inspect-c-users-swapn-appd
COPY ./src/aux/expressions.py /root/.local/lib/python3.11/site-packages/parsimonious/expressions.py
RUN npm ci --production
CMD [ "npm", "run", "start:prod" ]
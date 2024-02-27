# Build stage: compile Python dependencies
FROM python:3.10-alpine as builder
RUN apk update
RUN apk add alpine-sdk
RUN python3 -m pip install --upgrade pip
COPY requirements.txt ./
COPY forta_bot-0.2.0.tar.gz ./
RUN python3 -m pip install --user -r requirements.txt

# Final stage: copy over Python dependencies
FROM python:3.10-alpine
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local:$PATH
ENV FORTA_ENV=production
# Uncomment the following line to enable logging
LABEL "network.forta.settings.agent-logs.enable"="true"
WORKDIR /app
COPY ./src ./src
COPY LICENSE.md ./
CMD [ "python3", "./src/agent.py" ]
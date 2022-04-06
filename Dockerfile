FROM python:3.8-bullseye as base
FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt

FROM golang:1.18-bullseye AS go-build-env
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

FROM base
COPY --from=builder /install /usr/local
COPY --from=go-build-env /go/bin/dnsx /usr/local/bin/dnsx
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/dnsx_agent.py"]

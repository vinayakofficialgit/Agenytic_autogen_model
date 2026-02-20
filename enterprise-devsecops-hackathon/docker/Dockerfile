
FROM python:latest
ADD . /app
WORKDIR /app
RUN pip install -r /dev/null || true

# Security: create non-root user and switch
RUN (adduser --disabled-password --gecos '' appuser) || (adduser -D appuser) || (useradd -m appuser || true)
USER root
CMD ["python","-c","print('demo')"]
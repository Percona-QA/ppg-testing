FROM ubuntu:jammy

# Install packages and Python dependencies
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt -y install \
        apt-utils git vim sudo wget netcat python3 python3-pip \
        python3-dev build-essential && \
    apt -y upgrade && \
    python3 -m pip install cryptography pycrypto

# Clone and install PyKMIP
RUN git clone https://github.com/dutow/PyKMIP.git /opt/PyKMIP && \
    python3 /opt/PyKMIP/setup.py install

# Create directories
RUN mkdir -p /opt/certs /opt/polices

# Copy default policy
RUN cp /opt/PyKMIP/examples/policy.json /opt/polices

# Generate certificates
RUN python3 /opt/PyKMIP/bin/create_certificates.py -c /opt/certs

# Add server config (optional: copy a pre-created one instead)
RUN echo "[server]\n\
hostname=0.0.0.0\n\
port=5696\n\
certificate_path=/opt/certs/server_certificate.pem\n\
key_path=/opt/certs/server_key.pem\n\
ca_path=/opt/certs/root_certificate.pem\n\
policy_path=/opt/polices\n\
logging_level=DEBUG\n\
auth_suite=TLS1.2\n\
enable_tls_client_auth=True" > /opt/PyKMIP/server.conf

# Expose KMIP port
EXPOSE 5696

# Add entrypoint script
COPY entrypoint.sh /bin/entrypoint.sh
RUN chmod +x /bin/entrypoint.sh

CMD ["/bin/entrypoint.sh"]

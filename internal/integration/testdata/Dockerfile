# ---
# relationships:
#   verifies: agent
# ---

# The devcontainer image the Linux integration gate binds: the OpenBao CLI
# plus the OpenSSH client, and nothing that holds a credential.
FROM openbao/openbao:2.7.1
RUN apk add --no-cache openssh-client

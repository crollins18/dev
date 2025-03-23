FROM sflow/clab-frr

RUN apk add --no-cache openssh \
    && mkdir -p /var/run/sshd \
    && ssh-keygen -A \
    && adduser -D -s /usr/bin/vtysh frruser \
    && echo "frruser:frrpassword" | chpasswd \
    && adduser frruser frrvty \
    && echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
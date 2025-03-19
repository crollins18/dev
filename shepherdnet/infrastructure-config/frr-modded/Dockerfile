FROM sflow/clab-frr

RUN apk update && apk add --no-cache openssh
RUN mkdir -p /var/run/sshd && ssh-keygen -A
RUN adduser -D -s /usr/bin/vtysh frruser && echo "frruser:frrpassword" | chpasswd && adduser frruser frrvty
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

RUN echo "line vty" >> /etc/frr/frr.conf && \
    echo " transport input ssh" >> /etc/frr/frr.conf && \
    echo "username frruser password frrpassword" >> /etc/frr/frr.conf

RUN sed -i '1a\
/usr/sbin/sshd' /usr/lib/frr/docker-start
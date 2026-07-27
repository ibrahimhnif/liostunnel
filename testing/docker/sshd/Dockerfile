FROM alpine:3.21
RUN apk add --no-cache openssh-server \
 && adduser -D -s /bin/sh tunneluser \
 && echo 'tunneluser:tunnelpass' | chpasswd \
 && mkdir -p /home/tunneluser/.ssh
COPY keys/ssh_host_ed25519_key     /etc/ssh/ssh_host_ed25519_key
COPY keys/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
COPY keys/authorized_keys          /home/tunneluser/.ssh/authorized_keys
RUN chmod 600 /etc/ssh/ssh_host_ed25519_key /home/tunneluser/.ssh/authorized_keys \
 && chown -R tunneluser:tunneluser /home/tunneluser/.ssh \
 && printf 'AllowTcpForwarding yes\nPermitOpen any\nPasswordAuthentication yes\nPubkeyAuthentication yes\nPermitRootLogin no\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

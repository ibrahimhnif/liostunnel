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
 # Alpine's stock sshd_config already sets `AllowTcpForwarding no` earlier in
 # the file; OpenSSH takes the *first* occurrence of a global (non-Match)
 # directive, so merely appending `AllowTcpForwarding yes` below is silently
 # ignored and direct-tcpip channels get refused as AdministrativelyProhibited.
 # Rewrite the existing line in place instead of shadowing it.
 && sed -i 's/^AllowTcpForwarding no$/AllowTcpForwarding yes/' /etc/ssh/sshd_config \
 && printf 'PermitOpen any\nPasswordAuthentication yes\nPubkeyAuthentication yes\nPermitRootLogin no\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

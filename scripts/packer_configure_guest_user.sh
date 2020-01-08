#!/bin/bash

# Add new guest user
adduser graham

# Add no-password sudo config for graham user
echo "%graham ALL=NOPASSWD:ALL" > /etc/sudoers.d/graham
chmod 0440 /etc/sudoers.d/graham

# Add graham to sudo group
usermod -a -G sudo graham

# Install user key
mkdir -p /home/graham/.ssh
chmod 700 /home/graham/.ssh
cd /home/graham/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDB4nVp5hxEb9a9ie7BIC3SRB2yInqURv4koBWZYR8iIEHtAPrZSr+Px+bc6jgolt+byzQ0LbtZcVnQcrxaYtNG/UZ1wGMy/gC1LA3vbfqQgRtvaCdWdJrtwth8eIVLen4plV/XwK2MXk5DNg501zLjQt1E4POCTZdUXM2VISxyXDyruw77JyqYDOnMvKb6x6Jkio8ZnAOOtArUO+fhe7F/rftkgt8kya48e/gv0N1pBzrnbWPmt1eC8KVqNORzaclgWqrWX7aFYMfJdWY6EIkOneKlRHrBcZSI5qi/WNXYlKznLcKgiLkdWgYY2bnuEqgNLjp2+KSK0oEnILrKRFF5 graham@allthingscloud.eu' >> /home/graham/.ssh/authorized_keys
chmod 600 /home/graham/.ssh/authorized_keys
chown -R graham /home/graham
exit 0

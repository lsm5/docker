FROM 10.3.13.125:5000/brew/rhel7:latest
MAINTAINER scollier <scollier@redhat.com>

# Update the system
RUN yum -y update; yum clean all

# Add repo files
ADD ./mongo.repo /etc/yum.repos.d/

# Install MongoDB and extras
RUN yum -y install mongo-10gen-server mongo-10gen; yum clean all
RUN yum -y install procps-ng iptables; yum clean all

ADD ./mongod.conf /etc/

# Expose ports
EXPOSE 27017 28017

# USER mongod

CMD ["/usr/bin/mongod", "-f", "/etc/mongod.conf"]

FROM registry.access.redhat.com/redhat/rhel7beta
MAINTAINER scollier <scollier@redhat.com>

RUN yum -y update; yum clean all
RUN yum -y install mariadb-server mariadb pwgen psmisc; yum clean all

ADD ./config_mariadb.sh /config_mariadb.sh

# RUN echo %sudo	ALL=NOPASSWD: ALL >> /etc/sudoers

RUN chmod 755 /config_mariadb.sh
RUN /config_mariadb.sh

EXPOSE 3306

# CMD ["/bin/bash", "/start.sh"]
CMD ["/usr/bin/mysqld_safe" ]

FROM ubuntu-debootstrap:14.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update &&\
    apt-get install -y software-properties-common apt-transport-https &&\
    apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 CD2EFD2A &&\
    add-apt-repository 'deb http://flynn-apt.s3.amazonaws.com/ stable main' &&\
    add-apt-repository 'deb http://repo.percona.com/apt trusty main' &&\
    apt-get update &&\
    apt-get install -y sudo &&\
    apt-get install -y --allow-unauthenticated mariadb-server-10.1 percona-xtrabackup &&\
    apt-get clean &&\
    apt-get autoremove -y

ADD bin/flynn-mariadb /bin/flynn-mariadb
ADD bin/flynn-mariadb-api /bin/flynn-mariadb-api
ADD start.sh /bin/start-flynn-mariadb

ENTRYPOINT ["/bin/start-flynn-mariadb"]

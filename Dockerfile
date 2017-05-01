FROM ubuntu:14.04
MAINTAINER Changjoon Baek<changjoon.baek@gmail.com>

# Run upgrades
#RUN echo "deb http://archive.ubuntu.com/ubuntu precise main universe" > /etc/apt/sources.list
RUN echo "deb http://download.tizen.org/tools/latest-release/Ubuntu_14.04 /" >> /etc/apt/sources.list
RUN cat /etc/apt/sources.list
RUN apt-get update
RUN apt-get upgrade

# Install basic packages
RUN apt-get -y install git curl build-essential vim

# Install pkgs for tizen build(GBS)
RUN apt-get -y --force-yes install gbs

# Install gbs.conf
RUN echo "[general]\nprofile = profile.tizen3.0_mobile_emul\n[profile.tizen3.0_mobile_emul]\nrepos=repo.tizen3.0_emul_base,repo.tizen3.0_unified\n[repo.tizen3.0_emul_base]\nurl=https://download.tizen.org/snapshots/tizen/base/latest/repos/emulator32/packages/\n[repo.tizen3.0_unified]\nurl=https://download.tizen.org/snapshots/tizen/unified/latest/repos/emulator/packages/\n" > /gbs.mobile.emul.conf

RUN cat /gbs.mobile.emul.conf
RUN git clone https://github.com/Changjoon/ttrace.git -b tizen_3.0
RUN gbs -c /gbs.mobile.emul.conf build -A i586
RUN mkdir /output
RUN cp /root/GBS-ROOT/local/repos/tizen3.0_mobile_emul/i586/RPMS/*.rpm /output

CMD ["/bin/bash"]

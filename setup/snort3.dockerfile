# Originally based on https://github.com/MikeHorn-git/docker-snort3/blob/main/Dockerfile

FROM debian:bookworm-slim

ARG SNORT_VERSION=3.2.2.0
ARG DAQ_VERSION=3.0.15

ENV DEBIAN_FRONTEND noninteractive

# Snort dependencies
RUN apt-get update &&                                                                                                  \
    apt-get upgrade -y &&                                                                                              \
    apt-get install -y -q --no-install-recommends                                                                         \
        bison                                                                                                          \
        build-essential                                                                                                \
        ca-certificates                                                                                                \
        cmake                                                                                                          \
        libdumbnet-dev                                                                                                 \
        libfl-dev                                                                                                      \
        libhwloc-dev                                                                                                   \
        libluajit-5.1-dev                                                                                              \
        liblzma-dev                                                                                                    \
        libpcap-dev                                                                                                    \
        libpcre3-dev                                                                                                   \
        libssh-dev                                                                                                     \
        libtool                                                                                                        \
        pkg-config                                                                                                     \
        tar                                                                                                            \
        wget                                                                                                           \
        zlib1g-dev &&                                                                                                  \
    apt-get clean &&                                                                                                   \
    rm -rf /var/cache/apt/archives/*deb                                                                                \
        /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /snort/rules

WORKDIR /snort

# Install LibDAQ
RUN wget https://github.com/snort3/libdaq/archive/refs/tags/v${DAQ_VERSION}.tar.gz -O libdaq-${DAQ_VERSION}.tar.gz &&  \
    tar -xf libdaq-${DAQ_VERSION}.tar.gz &&                                                                            \
    cd libdaq-${DAQ_VERSION} &&                                                                                        \
    ./bootstrap &&                                                                                                     \
    ./configure &&                                                                                                     \
    make &&                                                                                                            \
    make install &&                                                                                                    \
    rm -rf /snort/libdaq-${DAQ_VERSION}.tar.gz                                                                         \
        /snort/libdaq-${DAQ_VERSION}

# Install Snort
RUN wget https://github.com/snort3/snort3/archive/refs/tags/${SNORT_VERSION}.tar.gz &&                                 \
    tar -xf ${SNORT_VERSION}.tar.gz &&                                                                                 \
    cd snort3-${SNORT_VERSION} &&                                                                                      \
    ./configure_cmake.sh --prefix=/snort &&                                                                            \
    cd build &&                                                                                                        \
    make -j "$(nproc)" install &&                                                                                      \
    rm -rf /snort/${SNORT_VERSION}.tar.gz                                                                              \
        /snort/snort3-${SNORT_VERSION}

# Get Snort community ruleset
RUN wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz &&                                    \
    tar -xzvf snort3-community-rules.tar.gz &&                                                                         \
    cp snort3-community-rules/snort3-community.rules /snort/rules &&                                                   \
    rm -rf snort3-community-rules.tar.gz                                                                               \
        /snort/snort3-community-rules

# Get Emerging Threats Ruleset and convert from Snort2 to Snort3
# See https://community.emergingthreats.net/t/snort3-snort2lua-and-the-emerging-threats-snort-2-9-ruleset/475
RUN mkdir -p snort2lua/rules/disabled snort2lua/conversion &&                                                          \
    cd snort2lua &&                                                                                                    \
    wget https://rules.emergingthreats.net/open/snort-${SNORT_VERSION}/emerging.rules.tar.gz &&                        \
    tar -xzvf ./emerging.rules.tar.gz &&                                                                               \
    mv rules/*deleted.rules rules/disabled &&                                                                          \
    cat rules/*.rules >> conversion/et_all.rules &&                                                                    \
    cd conversion &&                                                                                                   \
    /snort/bin/snort2lua -c et_all.rules -r et_snort3_all.rules || true &&                                             \
    sed '/^--\[\[/,/\]\]/d;s/--\[\[.*$//' snort.lua >> et_thresholds.tmp.lua &&                                        \
    sed -i 1,26d et_thresholds.tmp.lua &&                                                                              \
    sed -i -e '/!\$HOME_NET any/d' -e '/!\$SMTP_SERVERS any/d' -e '/!\[\$SMTP_SERVERS/d' et_snort3_all.rules &&        \
    head -n -6 et_thresholds.tmp.lua >> et_thresholds.lua &&                                                           \
    mv et_snort3_all.rules /snort/rules/ &&                                                                            \
    mv et_thresholds.lua /snort/etc/snort/ &&                                                                          \
    mv /snort/etc/snort/snort.lua /snort/etc/snort/snort.lua.bak &&                                                    \
    rm -rf /snort/snort2lua

COPY snort.lua /snort/etc/snort/
COPY start-snort.sh /snort/

RUN ldconfig
RUN chmod 550 /snort/start-snort.sh

# Requires the environment variable 'interfaces' to be set to an array of interface names - see compose file
ENTRYPOINT "/snort/start-snort.sh"


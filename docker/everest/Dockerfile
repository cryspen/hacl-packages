# This is the Everest Base Image
# Version 1
# If you make changes to this file, make sure to update the version above and rebuild the image,
# also update all references to use the new version, this image should be built using:
# docker build -f Dockerfile -t everest_base_image:$V .
# Where $V is the number of the version above
FROM ubuntu:focal

# Add a new mirror, maybe more stable than Docker's
# RUN echo 'deb http://mirror.pnl.gov/ubuntu/ focal main' >> /etc/apt/sources.list
# RUN echo "deb http://mirror.math.ucdavis.edu/ubuntu/ focal main" >> /etc/apt/sources.list

# Try to overcome the "Hash Sum Mismatch" failure by retrying if failed
RUN echo "Acquire::Retries \"16\";" > /etc/apt/apt.conf.d/99acquire-retries

# Commit changes
RUN apt-get --yes update

# Configure new PPA for mono
# from: https://www.mono-project.com/download/stable/#download-lin
RUN apt-get install --no-install-recommends --yes software-properties-common curl gnupg ca-certificates
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
RUN echo "deb https://download.mono-project.com/repo/ubuntu stable-focal main" | tee /etc/apt/sources.list.d/mono-official-stable.list
RUN apt-get --yes update

# Configure repository for node.js 14.x LTS
# from: https://github.com/nodesource/distributions/blob/master/README.md#debinstall
RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -

# Configure new PPA for python3.6
# from: https://askubuntu.com/questions/865554/how-do-i-install-python-3-6-using-apt-get
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get --yes update

# Here start the Everest-specific packages
RUN until apt-get install --no-install-recommends --yes \
        libssl-dev \
        libsqlite3-dev \
        g++ \
        gcc \
        m4 \
        make \
        opam \
        git \
        pandoc \
        pkg-config \
        python \
        libgmp3-dev \
        zip \
        unzip \
        build-essential \
        automake \
        ca-certificates-mono \
        fsharp \
        msbuild \
        libunwind8 \
        sudo \
        python3.6 \
        python3-pip \
        python3-setuptools \
        nuget \
        ca-certificates \
        cmake \
        libtool \
        autoconf \
        tzdata \
        openssh-server \
        vim \
        curl \
        wget \
        tcptraceroute \
        emacs \
        libc6 \
        libc6-dev \
        time \
        jq \
        nodejs \
        ; do apt-get --yes update ; done

#Make python3 point to python3.6 (since update-alternatives does not seem to be used here)
RUN ln -sf /usr/bin/python3.6 /usr/bin/python3

#Install sphinx (for the Low* tutorial)
RUN pip3 install sphinx==1.7.2 sphinx_rtd_theme

#Install scons
RUN wget https://downloads.sourceforge.net/project/scons/scons/3.0.1/scons-3.0.1.tar.gz
RUN tar xf scons-3.0.1.tar.gz
WORKDIR scons-3.0.1
RUN python3.6 setup.py install
WORKDIR ..

#install typescript
RUN npm install -g typescript

#install less
RUN npm install -g less

# Install madoko
RUN npm install madoko -g && npm install jsdoc -g

# Install node server
RUN npm install http-server -g

# Setup ssh
RUN mkdir /var/run/sshd

# Set root password
RUN echo root:Docker! | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# start service
RUN service ssh start

# Create user everest.
# We define a home directory by ourselves, because there is no way to have the HOME variable caught by WORKDIR.
# So, to make it consistent, we explicitly make this directory home when creating the user.
ENV MYHOME /home/everest
RUN useradd --shell /bin/bash --create-home --home-dir ${MYHOME} everest
RUN echo "everest ALL=(ALL:ALL) NOPASSWD:ALL" >> /etc/sudoers
RUN echo everest:Docker! | chpasswd

# --login: Ensure that the .profile is read at each subsequent RUN (to take all the settings and environment that opam will write there).
# Other options to bash may be added here, but -c MUST BE the last one (it introduces the actual command to be RUN)
SHELL ["/bin/bash", "--login", "-c"]

# Switch to user mode
USER everest
WORKDIR ${MYHOME}

# Prepare build (OCaml packages). Remove sandboxing once we upgrade to a saner
# version of Ubuntu
ENV opamv 4.12.0
ENV OPAMYES true
RUN opam init --auto-setup --disable-sandboxing --comp ${opamv} --yes

# Setup the user that will be used to interact with github.
RUN git config --global user.email "everbld@microsoft.com"
RUN git config --global user.name "Dzomo the everest Yak"

# Prepare Everest; we write the everest-specific settings into the GLOBAL
# /etc/profile so that all users benefit from them. Note: had to modify
# init_container.sh so that its dumb writeout of the entire environment goes
# before our customizations.
RUN git clone --branch protz_aarch64 https://github.com/project-everest/everest.git
RUN rm -rf .git
ENV EVEREST_ENV_DEST_FILE ${MYHOME}/.profile
RUN ./everest/everest --yes check
RUN eval $(opam config env)

RUN echo "echo \$(date -u '+%Y-%m-%d %H:%M:%S') > ~/mru.txt" >> ~/.bashrc

EXPOSE 22 80 443

# Set the final directory entrypoint
WORKDIR ${MYHOME}/everest

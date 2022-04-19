FROM hacl:aarch64

ARG everest_revision
ADD --chown=everest:everest generate.sh /home/everest/everest/
RUN chmod +x /home/everest/everest/generate.sh

SHELL ["/bin/bash", "-c"]
# git checkout $everest_revision
ENTRYPOINT ["/home/everest/everest/generate.sh"]

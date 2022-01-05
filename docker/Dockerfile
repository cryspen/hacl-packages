FROM everest_base_image:1

ARG hacl_revision

# Checkout the most recent everest revision that "knows" how to build the
# desired HACL version.
RUN git checkout $(git log -G $hacl_revision --pretty=format:"%h" | head -n 1)
RUN ./everest --yes FStar pull_projects FStar make --admit -j 8
RUN ./everest --yes kremlin pull_projects kremlin make --admit -j 8
RUN ./everest --yes pull_vale
RUN ./everest --yes hacl-star pull_projects hacl-star make -j 4

FROM everest_base_image:1

ARG everest_revision

# Checkout the most recent everest revision that "knows" how to build the
# desired HACL version.
RUN git checkout $everest_revision
RUN ./everest --yes hacl-star pull_projects
RUN ./everest --yes pull_vale
RUN ./everest --yes FStar pull_projects FStar make --admit -j 4
RUN ./everest --yes kremlin pull_projects kremlin make --admit -j 4
RUN OTHERFLAGS="--warn_error -282+16+19+303" OCAMLRUNPARAM=b=1 ./everest --yes hacl-star make -j 2

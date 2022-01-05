FROM everest_base_image:1

ARG hacl_revision

# Checkout the most recent everest revision that "knows" how to build the
# desired HACL version.
RUN git checkout $(git log -G $hacl_revision --pretty=format:"%h")
RUN ./everest FStar pull FStar make --admit -j 8
RUN ./everest kremlin pull kremlin make --admit -j 8
RUN ./everest pull_vale
RUN ./everest hacl-star pull hacl-star make -j 8

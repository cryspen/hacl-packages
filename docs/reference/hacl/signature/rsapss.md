# RSAPSS

RSASSA-PSS as defined in [RFC 8017].

## Available Implementations

```C
#include "Hacl_RSAPSS.h"
```

## API Reference

**Example**

```{literalinclude} ../../../../tests/rsapss.cc
:language: C
:dedent:
:start-after: "// ANCHOR(EXAMPLE)"
:end-before: "// ANCHOR_END(EXAMPLE)"
```

```{doxygenfunction} Hacl_RSAPSS_new_rsapss_load_skey
```

```{doxygenfunction} Hacl_RSAPSS_new_rsapss_load_pkey
```

```{doxygenfunction} Hacl_RSAPSS_rsapss_sign
```

```{doxygenfunction} Hacl_RSAPSS_rsapss_verify
```

--------------------------------------------------------------------------------

```{doxygenfunction} Hacl_RSAPSS_rsapss_skey_sign
```

```{doxygenfunction} Hacl_RSAPSS_rsapss_pkey_verify
```

[rfc 8017]: https://www.rfc-editor.org/rfc/rfc8017

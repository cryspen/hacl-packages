# HPKE

```{note}
This API is experimental and subject to change.
```

Hybrid public key encryption (HPKE) according to [RFC 9180].

## Available Implementations

``````````{tabs}
`````````{group-tab} Curve51
````````{tabs}
```````{group-tab} 32
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_Curve51_CP32_SHA256.h"
```
`````
`````{group-tab} SHA512
```c
#include "Hacl_HPKE_Curve51_CP32_SHA512.h"
```
`````
``````
```````
```````{group-tab} 128
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_Curve51_CP128_SHA256.h"
```
`````
`````{group-tab} SHA512
```c
#include "Hacl_HPKE_Curve51_CP128_SHA512.h"
```
`````
``````
```````
```````{group-tab} 256
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_Curve51_CP256_SHA256.h"
```
`````
`````{group-tab} SHA512
```c
#include "Hacl_HPKE_Curve51_CP256_SHA512.h"
```
`````
``````
```````
````````
`````````
`````````{group-tab} Curve64
````````{tabs}
```````{group-tab} 32
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_Curve64_CP32_SHA256.h"
```
`````
`````{group-tab} SHA512
```c
#include "Hacl_HPKE_Curve64_CP32_SHA512.h"
```
`````
``````
```````
```````{group-tab} 128
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_Curve64_CP128_SHA256.h"
```
`````
`````{group-tab} SHA512
```c
#include "Hacl_HPKE_Curve64_CP128_SHA512.h"
```
`````
``````
```````
```````{group-tab} 256
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_Curve64_CP256_SHA256.h"
```
`````
`````{group-tab} SHA512
```c
#include "Hacl_HPKE_Curve64_CP256_SHA512.h"
```
`````
``````
```````
````````
`````````
`````````{group-tab} P256
````````{tabs}
```````{group-tab} 32
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_P256_CP32_SHA256.h"
```
`````
`````{group-tab} SHA512
Not available.
`````
``````
```````
```````{group-tab} 128
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_P256_CP128_SHA256.h"
```
`````
`````{group-tab} SHA512
Not available.
`````
``````
```````
```````{group-tab} 256
``````{tabs}
`````{group-tab} SHA256
```c
#include "Hacl_HPKE_P256_CP256_SHA256.h"
```
`````
`````{group-tab} SHA512
Not available.
`````
``````
```````
````````
`````````
``````````


## API Reference

```c
#include "Hacl_HPKE_Interface_Hacl_Impl_HPKE_Hacl_Meta_HPKE.h"
```

```{doxygentypedef} Hacl_Impl_HPKE_context_s
```

``````````{tabs}
`````````{group-tab} Curve51
````````{tabs}
```````{group-tab} 32
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA256_openBase
```
`````
`````{group-tab} SHA512
```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA512_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA512_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA512_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP32_SHA512_openBase
```
`````
``````
```````
```````{group-tab} 128
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA256_openBase
```
`````
`````{group-tab} SHA512
```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA512_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA512_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA512_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP128_SHA512_openBase
```
`````
``````
```````
```````{group-tab} 256
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA256_openBase
```
`````
`````{group-tab} SHA512
```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA512_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA512_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA512_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve51_CP256_SHA512_openBase
```
`````
``````
```````
````````
`````````
`````````{group-tab} Curve64
````````{tabs}
```````{group-tab} 32
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA256_openBase
```
`````
`````{group-tab} SHA512
```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA512_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA512_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA512_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP32_SHA512_openBase
```
`````
``````
```````
```````{group-tab} 128
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA256_openBase
```
`````
`````{group-tab} SHA512
```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA512_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA512_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA512_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP128_SHA512_openBase
```
`````
``````
```````
```````{group-tab} 256
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA256_openBase
```
`````
`````{group-tab} SHA512
```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA512_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA512_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA512_sealBase
```

```{doxygenfunction} Hacl_HPKE_Curve64_CP256_SHA512_openBase
```
`````
``````
```````
````````
`````````
`````````{group-tab} P256
````````{tabs}
```````{group-tab} 32
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_P256_CP32_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_P256_CP32_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_P256_CP32_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_P256_CP32_SHA256_openBase
```
`````
`````{group-tab} SHA512
Not available.
`````
``````
```````
```````{group-tab} 128
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_P256_CP128_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_P256_CP128_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_P256_CP128_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_P256_CP128_SHA256_openBase
```
`````
`````{group-tab} SHA512
Not available.
`````
``````
```````
```````{group-tab} 256
``````{tabs}
`````{group-tab} SHA256
```{doxygenfunction} Hacl_HPKE_P256_CP256_SHA256_setupBaseS
```

```{doxygenfunction} Hacl_HPKE_P256_CP256_SHA256_setupBaseR
```

```{doxygenfunction} Hacl_HPKE_P256_CP256_SHA256_sealBase
```

```{doxygenfunction} Hacl_HPKE_P256_CP256_SHA256_openBase
```
`````
`````{group-tab} SHA512
Not available.
`````
``````
```````
````````
`````````
``````````

[rfc 9180]: https://www.rfc-editor.org/rfc/rfc9180.html

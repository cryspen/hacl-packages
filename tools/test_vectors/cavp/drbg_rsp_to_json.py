# WARNING: This script only works for CAVP DRBG no_reseed.
#          Tweek it manually to make it work with pr_false and pr_true.

import json


data = open("HMAC_DRBG.rsp").read()
data = data.split("\n\n")
data = list(map(lambda item: item.split("\n"), data))
data = data[:-1]


def transform(rsp, instance, pr):
    out = {
        "hash": instance,
        "AdditionalInput": [],
        "PredictionResistance": pr,
        # For pr_false and pr_true
        # "EntropyInputPR": [],
    }
    for item in rsp:
        tmp = item.split("=")
        key, value = tmp[0].strip(), tmp[1].strip()

        if key == "AdditionalInput":
            out[key].append(value)
        # For pr_false and pr_true
        # elif key == "EntropyInputPR":
        #    out[key].append(value)
        elif key == "COUNT":
            out["COUNT"] = int(value)
        else:
            assert key not in out
            out[key] = value

    return out


tests = []

current_instance = None
pr = None

for block in data:
    if block[0].startswith("["):
        current_instance = block[0][1:-1]
        if block[1].startswith("[PredictionResistance = False]"):
            pr = False
        elif block[1].startswith("[PredictionResistance = True]"):
            pr = True
        else:
            raise "Unexpected"

    elif current_instance:
        tests.append(transform(block, current_instance, pr))

print(json.dumps(tests, indent=2))

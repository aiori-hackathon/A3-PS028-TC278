# Client variants, the curl@he200 control and generated scenarios

This page covers two additions:
- **client variants**: curl run with a different configuration;
- **generated extension scenarios**: scenarios beyond the core set, made from a grid.

Neither changes the core dataset. C0 and S1–S6 are still defined only in
`src/config/scenarios.yaml`, and a test pins that file byte for byte.

No variant or generated-scenario session has been run yet, so this page has no results. It records
what to run and how the results will be checked.

## Client variants

`curl@he<N>` means curl run with `--happy-eyeballs-timeout-ms N`. The orchestrator, `run_matrix.py
--only`, `check_batch.py`, dataset manifests and `summarise.py` all accept this label.

**What a variant is.** It is a configuration of curl, not a third client. PS-028 asks for "2 client
implementations or versions", and those are curl and Chromium. The run records keep this clear:
- `client.name` is always the implementation (`curl`);
- `client.variant` holds the variant (`he200`);
- `client.config.happy_eyeballs_timeout_ms` holds the value actually passed (`200`). Plain curl
  keeps `"default (not set)"`.

**How it is shown.**
- Summaries put each variant right after plain curl.
- The dashboard lists variants under curl's heading, in curl's colour, with triangle points and
  hatched bars.
- The dashboard's opening paragraph counts implementations, not labels.
- A variant's scenario penalty is computed from its own C0, never from plain curl's.

**File names.** `@` is written as `-`, so `curl@he200` becomes `curl-he200` in run IDs and in every
file named after them. See
[the schema](run_record_schema.md#client-variants-and-file-names).

Chromium takes no variants.

## The curl@he200 validation control

curl's man page documents 200 ms as the default Happy Eyeballs timeout. So `curl@he200` should
behave exactly like plain curl. Checking that it does is the control.

```
sudo .venv/bin/python src/runner/run_matrix.py --only S1:curl@he200
sudo .venv/bin/python src/runner/run_matrix.py --only S1:curl          # same kernel, same code
# list both sessions in a manifest, e.g. docs/datasets/variant-control.md
# (clients: [curl, curl@he200], scenarios: [S1], reps: 20), then:
.venv/bin/python src/analysis/variant_control.py --dataset variant-control
```

`variant_control.py` compares the variant's median TCP setup time (packet-level) with two
references:

1. **Plain curl S1 in the same dataset.** This uses the same kernel and code, so it isolates the
   flag. It is the control proper.
2. **Plain curl S1 in the frozen core dataset** (median 222.221 ms). The core runs were measured on
   kernel 7.0.0-38; this host now runs 7.0.0-43. So a difference here mixes the flag with the
   kernel change and anything else that changed on the host. This makes it a cross-kernel
   comparison, not a clean control.

The kernels on both sides are read from the records and printed next to each delta.

The delta is reported as measured, and nothing is tuned to make it zero. A delta counts as
**non-trivial** when the two medians' 95% bootstrap CIs do not overlap. That is a descriptive flag,
not a significance test. For a non-trivial delta, the script prints a proposed limitation line for
the report. Adding it to the report is a manual step, and the line does not try to explain the
difference away.

## Generated extension scenarios

- **Grid:** [`src/config/scenario_grid.yaml`](../src/config/scenario_grid.yaml). Each entry has a
  family, a kind (`delay` or `loss`) and a list of values.
- **Generator:** `src/runner/scenario_grid.py`. It writes
  [`src/config/scenarios_generated.yaml`](../src/config/scenarios_generated.yaml), and
  `--check` (also run as a test) fails if that file no longer matches the grid.
- **Rules,** the same as in `scenarios.yaml`:
  - delay N ("+N ms RTT"): `delay_ms_each_way = 10 + N/2` and `verify_target = 20 + N` on that
    family. N must be even, so each direction gets a whole number of ms.
  - loss N: N% loss in each direction on that family, at baseline delay.
- **IDs:** `G` + family + `d`/`l` + N, for example `Gv6d200`. Every entry is marked
  `extension: true`. An ID that collides with C0 or S1–S6, or looks like a core ID, is rejected.
- **Current grid:** an IPv6 latency sweep at +100, +200, +250, +300, +350 and +400 ms. The values
  are provisional: they bracket the fallback points seen in the core data (curl's IPv4 attempt
  about 200 ms after its first IPv6 SYN, Chromium's about 300 ms). Pilots set the final values.
- **Partial loss is not runnable yet.** The lab's `verify.sh` passes a numeric target only at 0%
  loss, so it cannot check a partial-loss link. A generated loss scenario gets the target `loss:N`,
  and the orchestrator refuses it before changing anything in the lab. Running loss scenarios first
  needs a reviewed extension of `verify.sh`/`lib.sh`.

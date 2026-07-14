# vip

Verification IP for [Veryl] — reusable bus-functional models, memory models and
protocol checkers for the native simulator. The standard library ships the
interface definitions but nothing to exercise them; the components here connect
to those interfaces' own modports to drive, model and check the protocol.

Each protocol family lives in its own module. Today the repository covers the
**AXI** family; further families can be added the same way.

## AXI

Four AXI protocols are covered, each with a master (or source), a slave (or
sink) and a passive checker:

| Protocol    | `$comp` components                                             |
| ----------- | ------------------------------------------------------------- |
| AXI4-Lite   | `axi4_lite_master`, `axi4_lite_ram`, `axi4_lite_checker`      |
| AXI4-Stream | `axi4_stream_source`, `axi4_stream_sink`, `axi4_stream_checker`|
| AXI4 (full) | `axi4_master`, `axi4_ram`, `axi4_checker`                     |
| AXI3        | `axi3_master`, `axi3_ram`, `axi3_checker`                     |

Masters drive directed and randomized self-checking traffic, memory models
answer with configurable latency, backpressure and error responses, and
checkers enforce the AMBA rules and report coverage. Bus widths are taken from
the connected interface, so any width works.

## Usage

Instantiate a component against an interface instance in a `#[test]` module:

```veryl
inst bus: $std::axi4_lite_if::<demo_pkg>;

inst mst: $comp::axi4_lite_master (clk, rst, axi: bus.master );
inst chk: $comp::axi4_lite_checker(clk, rst, axi: bus.monitor);
inst ram: $comp::axi4_lite_ram    (clk, rst, axi: bus.slave  );
```

How verification components are written, registered and used is covered in the
[Veryl documentation]. The runnable testbenches under `examples/` (run by
`veryl test`) double as usage examples for each component's methods and
parameters.

## Limitations

The AXI components are samples, not sign-off-grade VIP. By design:

- Write data follows the address (`W`-before-`AW` is not modelled); reads are
  fully multi-outstanding and out-of-order.
- `AxCACHE` / `AxPROT` / `AxQOS` / `AxREGION` / `*USER` are ignored.
- The exclusive monitor is single-master, address-granular and single-beat.
- Value-returning methods are capped at 512 bits (the randomized paths keep
  wide data inside the component and work at any width).

## Development

```
cd component && cargo test   # per-component unit tests, incl. the AMBA compliance suite
veryl test                   # end-to-end demos on the simulator, from the project root
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

[Veryl]: https://veryl-lang.org
[Veryl documentation]: https://doc.veryl-lang.org

# Demonstration script

## Getting started

To initialize variables, source `examples/setup.sh` or `examples/setup.ps1` accordingly:

```bash
. ./examples/setup.sh
```

In other tab or pane, provision resources if needed:

```bash
azd up
```

While resources are provisioning - or in lieu of if already provisioned - talk about how this was inspired by the
1Password CLI and can be used to rewrite configuration files to avoid storing secrets or set process environment
variables ephemerally so secrets are available to other processes.

### Presentation settings

* Scaling: 125%
* Resolution: 1920x1080
* Editor font size: increase 4x
* Terminal font size: increase 4x

## Code samples

To navigate through bookmarks:

* Next: `Ctrl+Alt+L`
* Previous: `Ctrl+Alt+J`

1. *(Bookmark 1)* Start with example of initializing a client.
2. `F12` into `credential()` to show how we initial credentials.
3. Show the current call pattern that returns a `Future<Output = Result<Response<T>>>` and currently requires two
    `await`s but, in the future, most calls will only require a single `await` to get the model. Developers can still
    get a raw response and deserialize (or not) as appropriate.

4. *(Bookmark 2)* Show how we protect models from accidentally leaking PII.

    ```bash
    RUST_LOG=info,akv=debug cargo run -- read --name secret-1
    ```

    But if developers opt into full `Debug` implementation:

    ```bash
    RUST_LOG=info,akv=debug cargo run -F debug -- read --name secret-1
    ```

5. *(Bookmark 3)* Show `SafeDebug` and explains how implements `Debug` to elide members by default but can replicate
    built-in `Debug`. It may be worth noting that have a helper attribute macro `#[safe(true)]` that can opt members
    into normal formatting.

6. *(Bookmark 4)* Talk about how we'll expose pageables in an upcoming beta so developers can iterate through items
    across numerous pages. Developers will also be able to iterate through pages if that works better for them.

    Long-running operations (LROs) will work similarly.

## How to read the docs

You can directly navigate through the markdown files [here](./src) or build the book locally using `mdbook`.

## Prerequisites to build book

Install required packages

```bash
cargo install mdbook
cargo install mdbook-mermaid
cargo install mdbook-linkcheck
```

## Build the book

From the project root directory run:

```bash
mdbook build doc
```

Rendered book will be generated in `target/book` from root directory

## Serve the book locally

To open the book in your browser run:

```bash
mdbook serve doc --open
```

## Contributing

Information about how to contribute to the documentation can be found in the documentation chapter [here](http://localhost:3000/contributing/documentation.html)

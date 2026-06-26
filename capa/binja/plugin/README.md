![capa explorer](../../../.github/capa-explorer-logo.png)

capa explorer for Binary Ninja brings capa's Program Analysis workflow into the Binary Ninja sidebar. It runs capa against the current Binary Ninja database, shows rule matches in an interactive tree, lets you jump to matched addresses, and highlights selected rows in the disassembly so interesting features stand out quickly.

This first release focuses on Program Analysis only. The sidebar also persists cached results in the Binary Ninja database, so you can reopen a file and choose to load existing results or reanalyze with your current rules.

## Getting Started

### Installation

The recommended way to install the plugin is through the Binary Ninja Plugin Manager. The plugin declares `flare-capa` as a dependency, so Binary Ninja can install the Python package automatically.

If you are developing locally or need to install manually:

1. Install [flare-capa](https://pypi.org/project/flare-capa/) into Binary Ninja's Python environment.
2. Download and extract the [official capa rules](https://github.com/mandiant/capa-rules/releases) that match your installed capa version.

### Usage

1. Open a supported file in Binary Ninja.
2. Open the `FLARE capa explorer` sidebar.
3. Click `Analyze`.
4. If prompted, select a local directory containing capa rules.

After analysis completes, capa explorer displays rule matches in the `Program Analysis` tree.

## Tips

* Click `Analyze` to run capa against the current Binary Ninja database.
* If cached results already exist in the database, capa explorer asks whether to load them or reanalyze.
* Use `Settings` to update the local capa rules directory.
* Use `Limit results to current function` to focus the tree on the active function.
* Use `Show matches by function` to group results by function instead of by rule.
* Double-click the `Address` column to navigate to the selected location.
* Check a row to highlight matched instructions in Binary Ninja.
* Right-click a function row to rename the current Binary Ninja function and refresh the tree.
* Click `Save` to export the current Program Analysis document as JSON.

## Requirements

The plugin requires:

* Binary Ninja with Python 3.10 support
* `flare-capa` installed in Binary Ninja's Python environment
* A local capa rules directory

If Binary Ninja loads the plugin but capa cannot be imported, check the Binary Ninja log. The plugin reports the Python interpreter path and common dependency mismatch errors there.

## Development

This plugin lives in [`capa/binja/plugin`](https://github.com/mandiant/capa/tree/master/capa/binja/plugin) and is packaged with capa. For local development, install capa from source, place the plugin in your Binary Ninja plugins directory, and restart Binary Ninja after making changes.

# Screenshots

Every image here comes from a **real run** of the command shown in its title
bar, on Linux (bash 5 and PowerShell 7.4). Nothing was edited by hand.

- Terminal images: the command ran in a pseudo-terminal, then its ANSI output
  was converted to HTML (`ansi2html`) and captured with headless Chrome.
- Report images: the HTML report written by the tool (`-o report.html`),
  captured with headless Chrome. `REPORT_HOSTNAME=lab-pc` set the host label.
- ARP and DNS examples use the synthetic fixtures in `../../tests/fixtures/`
  (documentation and private IP ranges), so no real network was attacked.

To refresh them, run the same commands and take your own screenshots. Windows
Terminal or any terminal emulator works.

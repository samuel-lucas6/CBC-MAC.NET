[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/CBC-MAC.NET/blob/main/LICENSE)

# CBC-MAC.NET

A .NET implementation of length-prepend [CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC).

> **Warning**
> 
> Do **NOT** use this algorithm. It's **NOT** collision resistant, so it's not committing. Furthermore, the length-prepend is likely non-standard, and this implementation also isn't very efficient as it uses one-shot methods for simplicity.

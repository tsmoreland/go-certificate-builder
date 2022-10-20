# go-certificate-builder

An implementaton of [certificate-builder](https://github.com/tsmoreland/certificate-builder) (private repo) written in GO rathr than C#

Provides
- certificate builder - a builder pattern approach to constructing a self-signed certificate
- WriteFile - method used to write certificate to disk in either PEM or PFX format
- certificate factory - factory pattern of sorts for constructing certificates - could be considered a facade around certificate builder to build common certificate scenarios (root CA, certificate signed by root CA, or localhost certificate for web API)

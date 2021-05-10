# HTTP-Proxy

### Introduction

The HTTP proxy can essentially be described as a high-performance content filter that traffic flows through to reach you. It acts as an intermediary between the client browser and the destination web server. [Read More](https://oxylabs.io/blog/what-is-http-proxy) 

### Insight

This is a simple program that implements a parallel HTTP proxy server that accepts a GET request and makes it on behalf of the client. The HTTP proxy returns the response if succeeded to the client and a 404 if there was an error. 
The proxy also handles multiple clients in parallel.

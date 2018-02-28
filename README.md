# certainly - A tiny HTTPS reverse proxy for mutual TLS authentication
#### Version: 0.2 / "We Shall Overcome"

## Introduction
> "Build zero trust networks they said. It will be fun they said".

The perimeter is dead. Well, not dead - but definitely on life support.  
The "inside" should no longer be considered a safe space where all hosts and users can be completly trusted.  
If we really need to argue about this, I recommend first reading about [Google's perspective on it](https://cloud.google.com/beyondcorp) and the book ["Zero Trust Networks"](http://shop.oreilly.com/product/0636920052265.do)

There are a few practical ways of build zero trust networks.  

One method, while not perfect and a bit cumbersome, is to use mutual TLS authentication for services (sometimes clumsily called "client certificates").  
It is nice for a couple of reasons:
- The client can communicate securely with the service without trusting the underlying network
- The service can validate the client's identity directly in the TLS connection. There is no need for custom built authentication mechanisms, session handling or irritating passwords
- The exposure of application functionality is non-existent for clients without a trusted certificate. All an unauthenticated attacker would have to mess with is OpenSSL or whatever TLS stack you are using

Sure, this is all good - but in order to take advantage of all these wonderful benefits your application needs to be built with mutual TLS authentication in mind.  
It's not undoable, but it usually requires some work.  

With that said, just the minimized exposure provided by the mutual authentication is appealing.  
For web applications and APIs, it's quite easy to just bolt on a reverse proxy in front of the web server and configure it to require client authentication.  
There you go - you just zero trustified your application! (I skipped the part about rolling out certificates and private keys to clients, I'm afraid it would not help my argument)

Two months after I got this idea into my head, I ended up with running a nginx instance on most of my servers.  
I do not consider this a personal victory and find it a bit overkill.

In order to do something about this, I've started to hack on a small Go application with this single task in mind - perform mutual TLS authentication and proxy requests to a single URL.  
Fellow nerds, meet "certainly" - all contributions are appreciated!  


## Current state
Proof of concept - *do not* use this unless you know what you are doing!
Currently, the TLS settings of the HTTPS client for proxied requests are not configurable.  


## Project goals
- Easy to use: A few command line flags or environment variables should be all that is required to get it running
- Easy to deploy: Static binaries without no runtime dependencies
- Sane defaults: Only resonable cipher suites and TLS protocol versions should be enabled by default
- Minimalistic: Small and auditable code base using only the Go standard library


## Nice to have
- White listing of allowed client names, based on CN or something similar - perhaps with regex support
- Insertion of security headers in responses, such as HSTS
- Insertion of "Secure" attributes for cookies


## Example usage
```
$ ./certainly -target-url 'http://127.0.0.1:1980' -server-address ':443' -server-cert 'cert.pem' -server-key 'key.pem' -client-ca 'ca.pem' -add-hsts
```

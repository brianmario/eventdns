EventDns - An EventMachine based DNS server
====================

My goal of this project (to start) is nothing more than to learn how to write a DNS server using ruby.

Currently, I plan on taking full advantage of the ruby language in combination with EventMachine's sweetness
to eventually have a fully RFC 1035 compliant DNS server.

Goals
-----
* Dynamic configuration
 * database
 * web service(s)
 * monitored flat-file(s)
* Caching
 * in-memory
 * memcached
* API
 * REST? (json/xml)
 * Drb?
 * Both?

Dreams
------
* make use of drb
* everything written in C

Requirements
------------
* gems
 * eventmachine
 * dnsruby
* a sweet bike
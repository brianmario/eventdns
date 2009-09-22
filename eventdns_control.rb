require 'rubygems'
require 'daemons'

#TODO: DRY this up.
require 'logging'
require 'eventmachine'
require 'dnsruby'
require 'lib/Backend/http'
require 'lib/simplecache'
require 'lib/usebackend'
require 'lib/eventdns'
require 'yaml'

Daemons.run('eventdns.rb')

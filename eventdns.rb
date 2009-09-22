# encoding: UTF-8

require 'yaml'

require 'rubygems'
require 'logging'
require 'eventmachine'
require 'dnsruby'

$LOAD_PATH.push(File.dirname(__FILE__))
require 'lib/Backend/http'
require 'lib/simplecache'
require 'lib/usebackend'
require 'lib/eventdns'

# daemonize changes the directory to "/"
Dir.chdir(File.dirname(__FILE__))
CONFIG = YAML.load_file('config.yml')

logfile = File.new(CONFIG[:log_file], 'a') # Always append
$logger = Logging.logger(logfile)
$logger.level = CONFIG[:log_level]

#FIXME: On OS X (1Ghz PPC), queries take over 2000 miliseconds to complete. WTF?
EventMachine.run {
  connection = nil
  trap("INT") {
    $logger.info "ctrl+c caught, stopping server"
    connection.shutdown
    EventMachine.stop_event_loop
  }
  trap("TERM") {
    $logger.info "TERM caught, stopping server"
    connection.shutdown
    EventMachine.stop_event_loop
  }
  begin
    # These options are supposed to help things run better on Linux?
    # http://eventmachine.rubyforge.org/docs/EPOLL.html
    EventMachine.epoll
    EventMachine.kqueue
    connection = EventMachine.open_datagram_socket(CONFIG[:bind_address], CONFIG[:bind_port], EventDns)
    $logger.info "EventDns started"
    $logger.debug "Driver is: '#{CONFIG[:driver]}'"
  rescue Exception => e
    $logger.fatal "#{e.inspect}"
    $logger.fatal e.backtrace.join("\r\n")
    $logger.fatal "Do you need root access?"
    EventMachine.stop_event_loop
  end
}

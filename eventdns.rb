# encoding: UTF-8

require 'yaml'

require 'rubygems'
require 'logging'
require 'eventmachine'
require 'dnsruby'
require 'lib/Backend/http'
require 'lib/simplecache'

# daemonize changes the directory to "/"
Dir.chdir(File.dirname(__FILE__))
CONFIG = YAML.load_file('config.yml')

$logger = Logging.logger(STDOUT)
$logger.level = CONFIG[:log_level]

class UseBackend
  @backend = nil
  @cache = nil

  def initialize(backend='default')
    #FIXME: Throw an error if the backend doesn't exist.
    #TODO: Eventually we should just look for a Backend::#{backend}::Lookup class
    @backend = backend.to_sym
    @cache = SimpleCache.new()
  end

  def handle(q,packet)
    self.send @backend, q, packet
  end # handle

  def default(q,packet)
    $logger.debug "#{q.qname} is 127.0.0.1, handing back to client"
    record = Dnsruby::RR.create(:name => q.qname, :type => "A", :ttl => 360, :address => "127.0.0.1")
    packet.header.qr = 1 # This is a Query Response
    packet.header.aa = 1 # This is an Authoritative Answer
    packet.add_answer(record)
  end # default

  def http(q,packet)
    key = "#{q.qname}-#{q.qtype}-#{CONFIG[:base_url]}"
    query = @cache.get(key)
    if query == nil # cache miss
      $logger.debug "Cache miss :("
      begin
        lookup = Backend::HTTP::Lookup.new()
        value = lookup.query({:name => q.qname,:type => q.qtype},CONFIG[:base_url])
      rescue Exception => e
        $logger.error "Error running query: #{e.inspect}"
        value = nil
      end
      @cache.set(key,value)
      query = value
    end

    # We are always sending a Query Response
    packet.header.qr = true

    if q.qtype == 'SOA'
      # Recursion Available
      #FIXME: I'm only setting this for now since this flag always seems to be set on SOA replies ...
      packet.header.ra = true 
    else
      # This is an Authoritative Answer
      packet.header.aa = true 
    end 

    unless query.valid?
      $logger.debug "Sending NXDomain"
      packet.header.rcode='NXDomain'
      return
    end
  
    query.results.each do |result|
      return unless result.is_a? Backend::HTTP::RR
      $logger.debug "Adding answer: '#{result.to_s}'"
      packet.add_answer(Dnsruby::RR.create(result.to_s))
    end
  end # http

end # UseBackend

class EventDns < EventMachine::Connection
  @backend = nil
  attr_accessor :host, :port
  def initialize
    @backend = UseBackend.new(CONFIG[:driver])
    $logger.debug "Handling query via the #{CONFIG[:driver]} Backend."
  end
  
  def new_connection
    # http://nhw.pl/wp/2007/12/07/eventmachine-how-to-get-clients-ip-address
    host = get_peername[2,6].unpack("nC4")
    @port = host.shift
    @host = host.join(".")
    
    $logger.info "Incoming packet from: #{client_info}"
  end
  
  def client_info
    host+":"+port.to_s
  end
  
  def receive_data(data)
    new_connection
    
    if data.size > 0
      begin
        packet = Dnsruby::Message.decode(data)
      rescue Exception => e
        $logger.error "Error decoding packet: #{e.inspect}"
        $logger.error e.backtrace.join("\r\n")
        return
      end
      
      packet.question.each do |q|
        $logger.debug "#{client_info} requested an #{q.qtype} record for #{q.qname}"
        @backend.handle(q,packet)
      end
      
      begin
        send_datagram(packet.encode, host, port)
      rescue Exception => e
        $logger.error "Error decoding packet: #{e.inspect}"
        $logger.error e.backtrace.join("\r\n")
      end
    end
  end
  
end

#FIXME: On OS X (1Ghz PPC), queries take over 2000 miliseconds to complete. WTF?
EventMachine.run {
  trap("INT") {
    $logger.info "ctrl+c caught, stopping server"
    EventMachine.stop_event_loop
  }
  begin
    # These options are supposed to help things run better on Linux?
    # http://eventmachine.rubyforge.org/docs/EPOLL.html
    EventMachine.epoll
    EventMachine.kqueue
    EventMachine.open_datagram_socket(CONFIG[:bind_address], CONFIG[:bind_port], EventDns)
    $logger.info "EventDns started"
    $logger.debug "Driver is: '#{CONFIG[:driver]}'"
  rescue Exception => e
    $logger.fatal "#{e.inspect}"
    $logger.fatal e.backtrace.join("\r\n")
    $logger.fatal "Do you need root access?"
    EventMachine.stop_event_loop
  end
}

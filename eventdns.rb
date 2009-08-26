# encoding: UTF-8

require 'yaml'

require 'rubygems'
require 'logging'
require 'eventmachine'
require 'dnsruby'

# daemonize changes the directory to "/"
Dir.chdir(File.dirname(__FILE__))
CONFIG = YAML.load_file('config.yml')

$logger = Logging.logger(STDOUT)
$logger.level = CONFIG[:log_level]

def handle_question_via_default(q,packet)
  $logger.debug "#{q.qname} is 127.0.0.1, handing back to client"
  record = Dnsruby::RR.create(:name => q.qname, :type => "A", :ttl => 360, :address => "127.0.0.1")
  packet.add_answer(record)
  packet.add_authority(record)
end

def handle_question_via_httprr(q,packet)
  require 'lib/httprr'

  url = CONFIG[:base_url].to_s + q.qname.to_s
  $logger.debug "Looking up: '#{url}'"
  query = HTTPRRArray.new(url)
  unless query.valid?
    $logger.debug "Sending NXDomain"
    packet.header.rcode='NXDomain'
    next
  end
  
  query.results.each do |result|
    next unless result.is_a? HTTPRR
    $logger.debug "Adding answer: #{result.to_s}"
    packet.add_answer(Dnsruby::RR.create(result.to_s))
  end
  ## Do I need to do this?
  # packet.add_authority(something)
end

class EventDns < EventMachine::Connection
  attr_accessor :host, :port
  
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

        case CONFIG[:driver]
        when 'sqlite3'
          # TODO: implement record lookup in DB based on question packet
          $logger.debug "Handling query via default instead of sqlite3."
          handle_question_via_default(q,packet)
        when 'httprr'
          $logger.debug "Handling query via HTTPRR."
          handle_question_via_httprr(q,packet)
        else
          $logger.debug "Handling query via default method."
          handle_question_via_default(q,packet)
        end
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

EventMachine.run {
  trap("INT") {
    $logger.info "ctrl+c caught, stopping server"
    EventMachine.stop_event_loop
  }
  begin
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

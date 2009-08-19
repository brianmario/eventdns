
require 'rubygems'
require 'yaml'
require 'logger'
require 'eventmachine'
require 'dnsruby'

LOGGER = Logger.new(STDOUT)
LOGGER.level = Logger::DEBUG

# daemonize changes the directory to "/"
Dir.chdir(File.dirname(__FILE__))
CONFIG = YAML.load_file('config.yml')

class EventDns < EM::Connection
  attr_accessor :host, :port
  
  def new_connection
    host = self.get_peername[2,6].unpack("nC4") #http://nhw.pl/wp/2007/12/07/eventmachine-how-to-get-clients-ip-address
    @port = host.shift
    @host = host.join(".")
    
    LOGGER.info "Incoming packet from: #{client_info}"
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
        LOGGER.error "Error decoding packet: #{e.inspect}"
        LOGGER.error e.backtrace.join("\r\n")
        return
      end
      
      packet.question.each do |q|
        LOGGER.debug "#{self.client_info} requested an #{q.qtype} record for #{q.qname}"
        
        LOGGER.debug "#{q.qname} is 127.0.0.1, handing back to client"
        # TODO: implement record lookup in DB based on question packet
        packet.add_answer(Dnsruby::RR.create("#{q.qname}. 360 IN A 127.0.0.1"))
      end
      
      begin
        send_data(packet.encode)
      rescue Exception => e
        LOGGER.error "Error decoding packet: #{e.inspect}"
        LOGGER.error e.backtrace.join("\r\n")
      end
    end
  end
  
end

EM.run {
  trap("INT") {
    LOGGER.info "ctrl+c caught, stopping server"
    EM.stop_event_loop
  }
  begin
    EM.epoll
    EM.open_datagram_socket(CONFIG['bind_to'], 53, EventDns)
    LOGGER.info "EventDns started"
  rescue Exception => e
    LOGGER.fatal "#{e.inspect}"
    LOGGER.fatal e.backtrace.join("\r\n")
    LOGGER.fatal "Do you need root access?"
    EM.stop_event_loop
  end
}
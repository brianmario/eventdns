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
    
    LOGGER.info "#{self.client_info} connected"
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
        close_connection
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
      ensure
        close_connection_after_writing
        LOGGER.info "#{self.client_info} disconnected"
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
    EM.stop_event_loop
  end
}

# module Syckass
#   module DNSServer
#     require 'dnsruby'
#     
#     # gracefully capture CTRL+C
#     trap("INT") {
#       puts "ctrl+c caught, stopping server"
#       EventMachine::stop_event_loop
#     }
# 
#     def receive_data(data)
#       if data.length > 0
#         packet = Dnsruby::Message.decode(data)
#         puts "packet received, and parsed:"
#         puts packet.inspect
#         
#         # TODO: implement record lookup in DB based on question packet
#         packet.add_answer(Dnsruby::RR.create("w. 360 IN A 127.0.0.1"))
#         puts "sending response:"
#         puts packet.inspect
#         send_data(packet.encode)
#         puts "response sent"
#       else
#         puts "zero-length packet received, ignoring... (it's ok, the UDP spec allows for zero-length packets)"
#       end
#     end
#   end
# end